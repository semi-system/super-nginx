// Run: node src/paging.test.mjs   (node >= 22.18 strips the TS types)
import assert from 'node:assert/strict'
import { pageCount, clampPage, pageSlice, pageWindow } from './paging.ts'

assert.equal(pageCount(0, 10), 1)
assert.equal(pageCount(10, 10), 1)
assert.equal(pageCount(11, 10), 2)

assert.equal(clampPage(0, 5), 1)
assert.equal(clampPage(9, 5), 5)

const items = [1, 2, 3, 4, 5]
assert.deepEqual(pageSlice(items, 1, 2), [1, 2])
assert.deepEqual(pageSlice(items, 3, 2), [5])
// page past the end falls back to the last page, never an empty table
assert.deepEqual(pageSlice(items, 99, 2), [5])

assert.deepEqual(pageWindow(1, 1), [1])
assert.deepEqual(pageWindow(1, 5), [1, 2, '…', 5])
assert.deepEqual(pageWindow(5, 9), [1, '…', 4, 5, 6, '…', 9])
assert.deepEqual(pageWindow(2, 4), [1, 2, 3, 4])

console.log('paging ok')
