import * as React from "react"

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string
}

export function Card({ className = "", ...props }: CardProps) {
  return (
    <div
      className={`bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow-sm ${className}`}
      {...props}
    />
  )
}

export function CardHeader({ className = "", ...props }: CardProps) {
  return (
    <div
      className={`px-6 py-4 border-b border-gray-200 dark:border-gray-700 ${className}`}
      {...props}
    />
  )
}

export function CardTitle({ className = "", children, ...props }: CardProps) {
  return (
    <h3
      className={`text-lg font-semibold text-gray-900 dark:text-white ${className}`}
      {...props}
    >
      {children}
    </h3>
  )
}

export function CardContent({ className = "", ...props }: CardProps) {
  return (
    <div
      className={`px-6 py-4 ${className}`}
      {...props}
    />
  )
}

export function CardDescription({ className = "", children, ...props }: CardProps) {
  return (
    <p
      className={`text-sm text-gray-600 dark:text-gray-400 ${className}`}
      {...props}
    >
      {children}
    </p>
  )
}