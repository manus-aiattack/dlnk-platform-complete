import * as React from "react"

interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string
}

export function Alert({ className = "", ...props }: AlertProps) {
  return (
    <div
      className={`rounded-lg border border-yellow-200 bg-yellow-50 p-4 dark:border-yellow-800 dark:bg-yellow-900 ${className}`}
      role="alert"
      {...props}
    />
  )
}

export function AlertTitle({ className = "", children, ...props }: AlertProps) {
  return (
    <h5
      className={`mb-1 font-medium leading-none tracking-tight text-yellow-800 dark:text-yellow-200 ${className}`}
      {...props}
    >
      {children}
    </h5>
  )
}

export function AlertDescription({ className = "", children, ...props }: AlertProps) {
  return (
    <div
      className={`text-sm text-yellow-700 dark:text-yellow-300 ${className}`}
      {...props}
    >
      {children}
    </div>
  )
}