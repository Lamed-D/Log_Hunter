"""모호한 전달 관계를 임의 선택하지 않는 순수 메타데이터 색인 테스트입니다."""
import copy
import unittest
from unittest.mock import patch

from log_hunter.image.vss import BLOCK_SIZE, VSSBlockList
from log_hunter.image.vss_map import build_descriptor_map


def descriptor(original=0, stored=BLOCK_SIZE*9, flags=0, relative=0, bits=0):
    return {'original_offset': original, 'relative_offset': relative, 'store_offset': stored,
            'flags': flags, 'allocation_bitmap': bits, 'valid': True, 'entry_offset': 128}


def mapping(items, size=BLOCK_SIZE*12):
    return build_descriptor_map(VSSBlockList('synthetic-store', items, complete=True), size)


class VSSMapTests(unittest.TestCase):
    def test_plain_forward_overlay_reverse_and_input_immutable(self):
        items = [descriptor(), descriptor(BLOCK_SIZE, flags=2, bits=0x80000001),
                 descriptor(BLOCK_SIZE*2, stored=0, flags=1, relative=BLOCK_SIZE*3)]
        before = copy.deepcopy(items)
        result = mapping(items)
        self.assertTrue(result.complete)
        self.assertFalse(result.readable)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.reverse, {BLOCK_SIZE*3: BLOCK_SIZE*2})
        self.assertIsNone(result.blocks[BLOCK_SIZE]['base'])
        self.assertEqual(result.blocks[BLOCK_SIZE]['overlay']['allocation_bitmap'], 0x80000001)
        self.assertEqual(items, before)
        result.blocks[0]['base']['store_offset'] = 512
        self.assertEqual(items, before)

    def test_plain_and_overlay_either_order_preserve_both(self):
        for items in ([descriptor(), descriptor(flags=2, bits=1)],
                      [descriptor(flags=2, bits=1), descriptor()]):
            result = mapping(items)
            self.assertTrue(result.complete)
            self.assertEqual(result.blocks[0]['base']['flags'], 0)
            self.assertEqual(result.blocks[0]['overlay']['allocation_bitmap'], 1)

    def test_same_overlay_location_combines_bits(self):
        result = mapping([descriptor(flags=2, bits=1), descriptor(flags=2, bits=0x80000000)])
        self.assertTrue(result.complete)
        self.assertEqual(result.blocks[0]['overlay']['allocation_bitmap'], 0x80000001)
        result = mapping([descriptor(flags=2, bits=1), descriptor(stored=BLOCK_SIZE*10, flags=2, bits=2)])
        self.assertFalse(result.complete)
        self.assertEqual(result.blocks, {})
        self.assertTrue(result.errors)

    def test_overlay_continuation_retains_each_raw_descriptor(self):
        first = descriptor(flags=2, bits=1)
        continuation = {**descriptor(flags=2, relative=1, bits=0x80000002), 'entry_offset': 160}
        items = [first, continuation]
        before = copy.deepcopy(items)
        result = mapping(items)
        self.assertTrue(result.complete)
        overlay = result.blocks[0]['overlay']
        self.assertEqual(overlay['allocation_bitmap'], 0x80000003)
        self.assertEqual([d['relative_offset'] for d in overlay['source_descriptors']], [0, 1])
        self.assertEqual([d['entry_offset'] for d in overlay['source_descriptors']], [128, 160])
        self.assertEqual([d['allocation_bitmap'] for d in overlay['source_descriptors']], [1, 0x80000002])
        self.assertEqual(items, before)
        overlay['source_descriptors'][0]['allocation_bitmap'] = 0
        self.assertEqual(items, before)

    def test_orphan_or_conflicting_overlay_continuation_fails_closed(self):
        first = descriptor(flags=2, bits=1)
        continuation = descriptor(flags=2, relative=1, bits=2)
        for items in ([continuation, first],
                      [first, {**continuation, 'store_offset': BLOCK_SIZE * 10}],
                      [first, {**continuation, 'original_offset': BLOCK_SIZE}],
                      [first, {**continuation, 'relative_offset': 2}]):
            with self.subTest(items=items):
                result = mapping(items)
                self.assertFalse(result.complete)
                self.assertEqual(result.blocks, {})
                self.assertTrue(result.errors)

    def test_duplicate_base_and_reverse_target_fail_closed(self):
        for items in ([descriptor(), descriptor(stored=BLOCK_SIZE*10)],
                      [descriptor(stored=0, flags=1, relative=BLOCK_SIZE*3),
                       descriptor(BLOCK_SIZE, stored=0, flags=1, relative=BLOCK_SIZE*3)]):
            result = mapping(items)
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
            self.assertEqual(result.blocks, {})
            self.assertEqual(result.reverse, {})

    def test_interacting_forward_targets_and_cycles_require_normalization(self):
        cases = [[descriptor(BLOCK_SIZE), descriptor(stored=0, flags=1, relative=BLOCK_SIZE)],
                 [descriptor(stored=0, flags=1, relative=0)],
                 [descriptor(stored=0, flags=1, relative=BLOCK_SIZE),
                  descriptor(BLOCK_SIZE, stored=0, flags=1, relative=0)]]
        for items in cases:
            result = mapping(items)
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
            self.assertEqual(result.blocks, {})

    def test_invalid_fields_flags_and_alignment_are_not_trusted(self):
        changes = [{'valid': False}, {'flags': 8}, {'flags': 3}, {'store_offset': 0},
                   {'original_offset': 123}, {'original_offset': BLOCK_SIZE*12},
                   {'flags': 1, 'store_offset': 0, 'relative_offset': 123},
                   {'allocation_bitmap': 1}, {'flags': 2, 'allocation_bitmap': 2**32},
                   {'flags': 2, 'relative_offset': 1},
                   {'relative_offset': -1}, {'original_offset': True}]
        for change in changes:
            result = mapping([{**descriptor(), **change}])
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
        self.assertTrue(mapping([None]).errors)

    def test_unused_empty_incomplete_and_limits(self):
        self.assertTrue(mapping([]).complete)
        self.assertTrue(mapping([descriptor(original=2**64-1, stored=0, flags=4)]).complete)
        self.assertTrue(build_descriptor_map(VSSBlockList('test'), BLOCK_SIZE).errors)
        for size in (0, -1, True, '0'):
            self.assertTrue(mapping([], size).errors)
        with patch('log_hunter.image.vss_map.MAX_BLOCK_DESCRIPTORS', 0):
            self.assertTrue(mapping([descriptor()]).errors)

    def test_later_forward_target_is_rewritten_to_original_owner(self):
        items = [descriptor(stored=0, flags=1, relative=BLOCK_SIZE),
                 descriptor(BLOCK_SIZE, stored=BLOCK_SIZE*10)]
        before = copy.deepcopy(items)
        result = mapping(items)
        self.assertTrue(result.complete)
        self.assertEqual(result.reverse, {})
        self.assertEqual(set(result.blocks), {0})
        self.assertEqual(result.blocks[0]['base']['store_offset'], BLOCK_SIZE*10)
        self.assertEqual(result.blocks[0]['base']['original_offset_raw'], BLOCK_SIZE)
        self.assertEqual(result.rewrites, [{'entry_offset': 128, 'from_original': BLOCK_SIZE, 'to_original': 0}])
        self.assertEqual(items, before)

    def test_multiple_forward_rewrites_do_not_leave_stale_reverse_targets(self):
        result = mapping([descriptor(stored=0, flags=1, relative=BLOCK_SIZE),
                          descriptor(BLOCK_SIZE, stored=0, flags=1, relative=BLOCK_SIZE*2),
                          descriptor(BLOCK_SIZE*2, stored=BLOCK_SIZE*10)])
        self.assertTrue(result.complete)
        self.assertEqual(result.reverse, {})
        self.assertEqual(set(result.blocks), {0})
        self.assertEqual(len(result.rewrites), 2)
        self.assertEqual(result.blocks[0]['base']['original_offset_raw'], BLOCK_SIZE*2)

    def test_rewrite_preserves_owner_overlay(self):
        result = mapping([descriptor(flags=2, bits=1),
                          descriptor(stored=0, flags=1, relative=BLOCK_SIZE),
                          descriptor(BLOCK_SIZE, stored=BLOCK_SIZE*10)])
        self.assertTrue(result.complete)
        self.assertEqual(result.blocks[0]['overlay']['allocation_bitmap'], 1)
        self.assertEqual(result.blocks[0]['base']['store_offset'], BLOCK_SIZE*10)

    def test_ambiguous_target_or_return_cycle_clears_rewrite_evidence(self):
        cases = [[descriptor(stored=0, flags=1, relative=BLOCK_SIZE),
                  descriptor(BLOCK_SIZE, flags=2, bits=1), descriptor(BLOCK_SIZE)],
                 [descriptor(stored=0, flags=1, relative=BLOCK_SIZE),
                  descriptor(BLOCK_SIZE, stored=0, flags=1, relative=BLOCK_SIZE*2),
                  descriptor(BLOCK_SIZE*2, stored=0, flags=1, relative=0)]]
        for items in cases:
            result = mapping(items)
            self.assertFalse(result.complete)
            self.assertTrue(result.errors)
            self.assertEqual(result.blocks, {})
            self.assertEqual(result.reverse, {})
            self.assertEqual(result.rewrites, [])
