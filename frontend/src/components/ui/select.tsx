import * as React from "react"

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  className?: string
}

export function Select({ className = "", ...props }: SelectProps) {
  return (
    <select
      className={`flex h-10 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm
        focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500
        disabled:cursor-not-allowed disabled:opacity-50 ${className}`}
      {...props}
    />
  )
}

interface SelectTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  className?: string
}

export function SelectTrigger({ className = "", children, ...props }: SelectTriggerProps) {
  return (
    <button
      className={`flex h-10 w-full items-center justify-between rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm
        focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500
        ${className}`}
      {...props}
    >
      {children}
      <svg
        className="ml-2 h-4 w-4"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
      </svg>
    </button>
  )
}

interface SelectValueProps extends React.HTMLAttributes<HTMLSpanElement> {
  placeholder?: string
  className?: string
}

export function SelectValue({ placeholder = "", className = "", ...props }: SelectValueProps) {
  return (
    <span className={`text-gray-500 dark:text-gray-400 ${className}`} {...props}>
      {placeholder}
    </span>
  )
}

interface SelectContentProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string
}

export function SelectContent({ className = "", children, ...props }: SelectContentProps) {
  return (
    <div
      className={`absolute z-50 mt-1 w-full rounded-md bg-white dark:bg-gray-800 shadow-lg ${className}`}
      {...props}
    >
      {children}
    </div>
  )
}

interface SelectItemProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string
}

export function SelectItem({ className = "", children, ...props }: SelectItemProps) {
  return (
    <div
      className={`px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer ${className}`}
      {...props}
    >
      {children}
    </div>
  )
}