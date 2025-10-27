import * as React from "react"

interface TabsProps extends React.HTMLAttributes<HTMLDivElement> {
  defaultValue?: string
  value?: string
  onValueChange?: (value: string) => void
  className?: string
}

export function Tabs({ className = "", children, ...props }: TabsProps) {
  const [value, setValue] = React.useState(props.defaultValue || "")

  return (
    <div className={`space-y-4 ${className}`} {...props}>
      {React.Children.map(children, child => {
        if (React.isValidElement(child)) {
          return React.cloneElement(child as React.ReactElement<any>, {
            value,
            onValueChange: setValue
          })
        }
        return child
      })}
    </div>
  )
}

interface TabsListProps extends React.HTMLAttributes<HTMLDivElement> {
  className?: string
}

export function TabsList({ className = "", ...props }: TabsListProps) {
  return (
    <div
      className={`grid grid-cols-2 gap-2 p-1 bg-gray-100 dark:bg-gray-800 rounded-lg ${className}`}
      {...props}
    />
  )
}

interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string
  className?: string
}

export function TabsTrigger({
  value,
  className = "",
  children,
  onClick,
  ...props
}: TabsTriggerProps) {
  return (
    <button
      className={`px-4 py-2 text-sm font-medium rounded-md transition-all
        hover:bg-white dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-white
        ${className}`}
      onClick={onClick}
      {...props}
    >
      {children}
    </button>
  )
}

interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string
  className?: string
}

export function TabsContent({
  value,
  className = "",
  children,
  ...props
}: TabsContentProps) {
  return (
    <div
      className={`w-full ${className}`}
      {...props}
    >
      {children}
    </div>
  )
}