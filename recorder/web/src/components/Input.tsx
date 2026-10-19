import * as React from "react";
import { cn } from "@utils/helpers";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  icon?: React.ReactNode;
  suffix?: React.ReactNode;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, icon, suffix, ...props }, ref) => {
    if (icon) {
      return (
        <div className="relative flex-1">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-nb-gray-400 pointer-events-none">
            {icon}
          </span>
          <input
            ref={ref}
            {...props}
            className={cn(
              "w-full bg-nb-gray-900 placeholder:text-neutral-400/70 border-nb-gray-700 text-sm",
              "rounded-md border py-2.5 pl-9 pr-3 text-gray-100 outline-hidden",
              "focus-visible:ring-2 focus-visible:ring-neutral-500/20",
              suffix && "pr-14!",
              className,
            )}
          />
          {suffix && (
            <span className="absolute right-3 top-1/2 -translate-y-1/2">{suffix}</span>
          )}
        </div>
      );
    }
    return (
      <input
        ref={ref}
        {...props}
        className={cn(
          "bg-nb-gray-900 placeholder:text-neutral-400/70 border-nb-gray-700 text-sm",
          "rounded-md border py-2.5 px-3 text-gray-100 outline-hidden",
          "focus-visible:ring-2 focus-visible:ring-neutral-500/20",
          className,
        )}
      />
    );
  },
);
Input.displayName = "Input";

export default Input;
