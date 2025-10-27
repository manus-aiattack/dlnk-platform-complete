import * as React from "react"

interface TableProps extends React.HTMLAttributes<HTMLTableElement> {
  className?: string
}

export function Table({ className = "", ...props }: TableProps) {
  return (
    <div className="relative w-full overflow-auto">
      <table
        className={`w-full caption-bottom text-sm ${className}`}
        {...props}
      />
    </div>
  )
}

export function TableHeader({ className = "", ...props }: TableProps) {
  return (
    <thead className={`[&_tr]:border-b ${className}`} {...props} />
  )
}

export function TableBody({ className = "", ...props }: TableProps) {
  return (
    <tbody className={`[&_tr:last-child]:border-0 ${className}`} {...props} />
  )
}

export function TableRow({ className = "", ...props }: TableProps) {
  return (
    <tr
      className={`border-b transition-colors hover:bg-gray-50 dark:hover:bg-gray-700 ${className}`}
      {...props}
    />
  )
}

export function TableHead({ className = "", ...props }: TableProps) {
  return (
    <th
      className={`h-12 px-4 text-left align-middle font-medium text-gray-500 dark:text-gray-400 [&:has([role=checkbox])]:pr-0 ${className}`}
      {...props}
    />
  )
}

export function TableCell({ className = "", ...props }: TableProps) {
  return (
    <td
      className={`p-4 align-middle [&:has([role=checkbox])]:pr-0 ${className}`}
      {...props}
    />
  )
}