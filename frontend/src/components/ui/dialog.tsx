import * as React from "react"

interface DialogProps extends React.HTMLAttributes<HTMLDivElement> {
  open?: boolean
  onOpenChange?: (open: boolean) => void
  className?: string
}

export function Dialog({ className = "", children, ...props }: DialogProps) {
  return (
    <div className={`relative z-50 ${className}`} {...props}>
      {children}
    </div>
  )
}

interface DialogTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  className?: string
}

export function DialogTrigger({ className = "", children, ...props }: DialogTriggerProps) {
  return (
    <button className={`inline-flex items-center ${className}`} {...props}>
      {children}
    </button>
  )
}

interface DialogContentProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string
}

export function DialogContent({ className = "", children, ...props }: DialogContentProps) {
  return (
    <div
      className={`fixed inset-0 flex items-center justify-center p-4 ${className}`}
      {...props}
    >
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-xl">
        {children}
      </div>
    </div>
  )
}

interface DialogHeaderProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string
}

export function DialogHeader({ className = "", children, ...props }: DialogHeaderProps) {
  return (
    <div className={`flex flex-col space-y-1.5 text-center sm:text-left ${className}`} {...props}>
      {children}
    </div>
  )
}

interface DialogTitleProps extends React.HTMLAttributes<HTMLHeadingElement> {
  className?: string
}

export function DialogTitle({ className = "", children, ...props }: DialogTitleProps) {
  return (
    <h2
      className={`text-lg font-semibold leading-none tracking-tight ${className}`}
      {...props}
    >
      {children}
    </h2>
  )
}

interface DialogDescriptionProps extends React.HTMLAttributes<HTMLParagraphElement> {
  className?: string
}

export function DialogDescription({ className = "", children, ...props }: DialogDescriptionProps) {
  return (
    <p
      className={`text-sm text-gray-500 dark:text-gray-400 ${className}`}
      {...props}
    >
      {children}
    </p>
  )
}

interface DialogFooterProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string
}

export function DialogFooter({ className = "", children, ...props }: DialogFooterProps) {
  return (
    <div className={`flex justify-end space-x-2 ${className}`} {...props}>
      {children}
    </div>
  )
}