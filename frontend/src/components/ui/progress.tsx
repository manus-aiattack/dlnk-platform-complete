import * as React from "react"

interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number
  max?: number
  className?: string
}

export function Progress({ value = 0, max = 100, className = "", ...props }: ProgressProps) {
  return (
    <div
      className={`w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 ${className}`}
      {...props}
    >
      <div
        className="bg-blue-600 h-2 rounded-full transition-all"
        style={{ width: `${(value / max) * 100}%` }}
      />
    </div>
  )
}