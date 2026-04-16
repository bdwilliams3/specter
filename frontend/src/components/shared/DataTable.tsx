import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  getFacetedRowModel,
  getFacetedUniqueValues,
  flexRender,
  type ColumnDef,
  type SortingState,
  type ColumnFiltersState,
  type FilterFn,
} from '@tanstack/react-table'

// Extend TanStack Table's FilterFns registry so 'multiSelect' is a valid string key
declare module '@tanstack/react-table' {
  interface FilterFns {
    multiSelect: FilterFn<unknown>
  }
}
import { useState, useRef, useEffect } from 'react'
import { ChevronLeft, ChevronRight, ChevronsUpDown, ArrowUp, ArrowDown, ListFilter, X } from 'lucide-react'

// ── Multi-select filter function ─────────────────────────────────────────────
const multiSelectFilter: FilterFn<unknown> = (row, columnId, selected: string[]) => {
  if (!selected?.length) return true
  const val = String(row.getValue(columnId) ?? '')
  return selected.includes(val)
}
multiSelectFilter.autoRemove = (val: unknown) => !(val as string[])?.length

// ── Sort icon ────────────────────────────────────────────────────────────────
function SortIcon({ dir }: { dir: 'asc' | 'desc' | false }) {
  if (dir === 'asc')  return <ArrowUp   size={11} className="text-specter-accent shrink-0" />
  if (dir === 'desc') return <ArrowDown size={11} className="text-specter-accent shrink-0" />
  return <ChevronsUpDown size={11} className="text-slate-700 group-hover:text-slate-500 shrink-0 transition-colors" />
}

// ── Per-column multi-select dropdown ────────────────────────────────────────
function FacetDropdown({ column }: { column: ReturnType<ReturnType<typeof useReactTable>['getColumn']> }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  // close on outside click
  useEffect(() => {
    if (!open) return
    const handle = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [open])

  if (!column) return null

  const facetMap   = column.getFacetedUniqueValues()
  const options    = Array.from(facetMap.keys())
    .filter(v => v != null && v !== '')
    .map(String)
    .sort()
  const selected   = (column.getFilterValue() as string[]) ?? []
  const active     = selected.length > 0

  const toggle = (val: string) => {
    const next = selected.includes(val)
      ? selected.filter(v => v !== val)
      : [...selected, val]
    column.setFilterValue(next.length ? next : undefined)
  }

  if (!options.length) return null

  return (
    <div ref={ref} className="relative shrink-0">
      <button
        onClick={e => { e.stopPropagation(); setOpen(o => !o) }}
        className={`flex items-center gap-0.5 rounded px-1 py-0.5 transition-colors ${
          active
            ? 'text-specter-accent bg-specter-accent/10'
            : 'text-slate-600 hover:text-slate-300 hover:bg-specter-border/60'
        }`}
        title="Filter column"
      >
        <ListFilter size={11} />
        {active && (
          <span className="text-[10px] font-bold leading-none">{selected.length}</span>
        )}
      </button>

      {open && (
        <div className="absolute left-0 top-full mt-1 z-50 min-w-[140px] max-h-60 overflow-y-auto bg-specter-surface border border-specter-border rounded-lg shadow-2xl py-1">
          {active && (
            <button
              onClick={() => { column.setFilterValue(undefined); setOpen(false) }}
              className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-slate-400 hover:text-white hover:bg-specter-border/60 transition-colors border-b border-specter-border mb-1"
            >
              <X size={10} /> Clear
            </button>
          )}
          {options.map(val => (
            <label
              key={val}
              className="flex items-center gap-2.5 px-3 py-1.5 cursor-pointer hover:bg-specter-border/60 transition-colors"
            >
              <input
                type="checkbox"
                checked={selected.includes(val)}
                onChange={() => toggle(val)}
                className="accent-specter-accent w-3 h-3 shrink-0"
              />
              <span className="text-xs text-slate-300 capitalize truncate">{val}</span>
              <span className="ml-auto text-[10px] text-slate-600 tabular-nums">
                {facetMap.get(val) ?? 0}
              </span>
            </label>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Skeleton ─────────────────────────────────────────────────────────────────
function SkeletonRow({ cols }: { cols: number }) {
  return (
    <tr>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-specter-border rounded animate-pulse" style={{ width: `${55 + (i * 17) % 35}%` }} />
        </td>
      ))}
    </tr>
  )
}

// ── Props ────────────────────────────────────────────────────────────────────
interface PaginationProps {
  page: number
  pageSize: number
  total: number
  onPageChange: (page: number) => void
}

interface DataTableProps<T> {
  columns: ColumnDef<T, unknown>[]
  data: T[]
  isLoading?: boolean
  pagination?: PaginationProps
  onRowClick?: (row: T) => void
}

// ── Table ────────────────────────────────────────────────────────────────────
export default function DataTable<T>({
  columns,
  data,
  isLoading,
  pagination,
  onRowClick,
}: DataTableProps<T>) {
  const [sorting, setSorting]           = useState<SortingState>([])
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])

  const table = useReactTable({
    data,
    columns,
    filterFns: { multiSelect: multiSelectFilter },
    state: { sorting, columnFilters },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel:          getCoreRowModel(),
    getSortedRowModel:        getSortedRowModel(),
    getFilteredRowModel:      getFilteredRowModel(),
    getFacetedRowModel:       getFacetedRowModel(),
    getFacetedUniqueValues:   getFacetedUniqueValues(),
    manualPagination: true,
  })

  const totalPages = pagination ? Math.ceil(pagination.total / pagination.pageSize) : 1
  const activeFilters = columnFilters.length

  return (
    <div className="flex flex-col gap-0">
      {activeFilters > 0 && (
        <div className="flex items-center justify-end px-1 pb-1.5">
          <button
            onClick={() => setColumnFilters([])}
            className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors"
          >
            <X size={10} /> Clear {activeFilters} filter{activeFilters > 1 ? 's' : ''}
          </button>
        </div>
      )}

      <div className="overflow-x-auto rounded border border-specter-border">
        <table className="w-full text-sm text-slate-300">
          <thead>
            {table.getHeaderGroups().map(hg => (
              <tr key={hg.id} className="border-b border-specter-border bg-specter-surface">
                {hg.headers.map(header => {
                  const canSort   = header.column.getCanSort()
                  const canFilter = header.column.getCanFilter()
                  return (
                    <th
                      key={header.id}
                      className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400"
                    >
                      <div className="flex items-center gap-1.5">
                        {/* Sort trigger — only wraps the label */}
                        <button
                          disabled={!canSort}
                          onClick={canSort ? header.column.getToggleSortingHandler() : undefined}
                          className={`flex items-center gap-1 group ${canSort ? 'cursor-pointer hover:text-slate-200 transition-colors' : 'cursor-default'}`}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {canSort && <SortIcon dir={header.column.getIsSorted()} />}
                        </button>

                        {/* Filter dropdown — separate from sort */}
                        {canFilter && (
                          <FacetDropdown column={header.column as Parameters<typeof FacetDropdown>[0]['column']} />
                        )}
                      </div>
                    </th>
                  )
                })}
              </tr>
            ))}
          </thead>

          <tbody>
            {isLoading
              ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} cols={columns.length} />)
              : table.getRowModel().rows.length === 0
              ? (
                <tr>
                  <td colSpan={columns.length} className="px-4 py-12 text-center text-slate-500">
                    No data found
                  </td>
                </tr>
              )
              : table.getRowModel().rows.map(row => (
                <tr
                  key={row.id}
                  onClick={() => onRowClick?.(row.original)}
                  className={`border-b border-specter-border/50 hover:bg-specter-surface/60 transition-colors ${onRowClick ? 'cursor-pointer' : ''}`}
                >
                  {row.getVisibleCells().map(cell => (
                    <td key={cell.id} className="px-4 py-3">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {pagination && totalPages > 1 && (
        <div className="flex items-center justify-between px-1 py-3 text-sm text-slate-400">
          <span>
            Showing {(pagination.page - 1) * pagination.pageSize + 1}–
            {Math.min(pagination.page * pagination.pageSize, pagination.total)} of {pagination.total}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => pagination.onPageChange(pagination.page - 1)}
              disabled={pagination.page <= 1}
              className="p-1 rounded hover:bg-specter-border disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft size={16} />
            </button>
            {Array.from({ length: Math.min(totalPages, 7) }).map((_, i) => {
              const p = i + 1
              return (
                <button
                  key={p}
                  onClick={() => pagination.onPageChange(p)}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${
                    pagination.page === p ? 'bg-specter-accent text-white' : 'hover:bg-specter-border'
                  }`}
                >
                  {p}
                </button>
              )
            })}
            <button
              onClick={() => pagination.onPageChange(pagination.page + 1)}
              disabled={pagination.page >= totalPages}
              className="p-1 rounded hover:bg-specter-border disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
