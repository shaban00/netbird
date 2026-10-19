"use client";

import React, { forwardRef } from "react";
import { cva, VariantProps } from "class-variance-authority";
import classNames from "classnames";

export type ButtonVariants = VariantProps<typeof buttonVariants>;

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    ButtonVariants {
  disabled?: boolean;
}

export const buttonVariants = cva(
  [
    "relative",
    "text-sm focus:z-10 focus:ring-2 font-medium focus:outline-hidden whitespace-nowrap shadow-xs",
    "inline-flex gap-2 items-center justify-center transition-colors focus:ring-offset-1",
    "cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed",
  ],
  {
    variants: {
      variant: {
        default: [
          "focus:ring-zinc-800/50 bg-nb-gray text-gray-400 border-gray-700/30 hover:text-white hover:bg-zinc-800/50",
        ],
        primary: [
          "focus:ring-netbird-600/50 ring-offset-neutral-950/50 enabled:bg-netbird disabled:bg-nb-gray-910 text-gray-100 enabled:hover:text-white enabled:hover:bg-netbird-500/80",
        ],
        secondary: [
          "ring-offset-neutral-950/50 focus:ring-neutral-500/20",
          "bg-nb-gray-920 text-gray-400 border-gray-700/40 hover:text-white hover:bg-nb-gray-910",
        ],
        danger: [
          "focus:ring-red-700/20 focus:bg-red-700 hover:bg-red-700 hover:border-red-800/50 bg-red-600 text-red-100",
        ],
      },
      size: {
        xs: "text-xs py-2 px-4",
        sm: "text-sm py-2.5 px-4",
        md: "text-md py-2.5 px-4",
        icon: "p-2.5",
      },
      rounded: {
        true: "rounded-md",
        false: "",
      },
      border: {
        0: "border",
        1: "border border-transparent",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "md",
      rounded: true,
      border: 1,
    },
  },
);

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant, rounded, border, size, ...props }, ref) => {
    return (
      <button
        type="button"
        {...props}
        ref={ref}
        className={classNames(
          buttonVariants({ variant, rounded, border, size }),
          props.className,
        )}
      >
        {props.children}
      </button>
    );
  },
);

Button.displayName = "Button";

export default Button;
