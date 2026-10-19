import * as React from "react";
import { cn } from "@utils/helpers";
import { cva, VariantProps } from "class-variance-authority";

export type BadgeVariants = VariantProps<typeof variants>;

interface Props extends React.HTMLAttributes<HTMLDivElement>, BadgeVariants {
  children: React.ReactNode;
  className?: string;
}

const variants = cva("", {
  variants: {
    variant: {
      red: ["bg-red-950/40 border-red-500 border text-red-500"],
      gray: ["bg-nb-gray-930/60 border-nb-gray-800/40 text-nb-gray-300 border"],
      green: ["bg-green-950 border-green-500 border text-green-400"],
      yellow: ["bg-yellow-950 border-yellow-500 border text-yellow-400"],
      blue: ["bg-blue-950 border-blue-500 border text-blue-400"],
      netbird: ["bg-netbird-950 border-netbird-500 border text-netbird-500"],
    },
    size: {
      default: "text-[0.75rem] py-1.5 px-3",
      xs: "text-[0.6rem] py-[0.3rem] px-2",
    },
  },
  defaultVariants: {
    variant: "gray",
    size: "default",
  },
});

export default function Badge({
  children,
  className,
  variant,
  size,
  ...props
}: Readonly<Props>) {
  return (
    <div
      className={cn(
        "relative cursor-inherit whitespace-nowrap rounded-md font-normal flex gap-1.5 items-center justify-center transition-all uppercase tracking-wide",
        variants({ variant, size }),
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}
