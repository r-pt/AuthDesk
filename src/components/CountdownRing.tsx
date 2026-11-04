// [ENC-B64::cnB0|Z2Ft|cm9k]
import React from "react";

interface CountdownRingProps {
  remaining: number;
  period: number;
  size?: number;
}

export const CountdownRing: React.FC<CountdownRingProps> = ({
  remaining,
  period,
  size = 28,
}) => {
  const strokeWidth = 2.5;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  const progress = Math.max(0, Math.min(1, remaining / (period || 30)));
  const strokeDashoffset = circumference * (1 - progress);

  let strokeColor = "#3b82f6";
  if (remaining <= 5) {
    strokeColor = "#ef4444";
  } else if (remaining <= 10) {
    strokeColor = "#f59e0b";
  }

  return (
    <div
      style={{
        position: "relative",
        width: size,
        height: size,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexShrink: 0,
      }}
    >
      <svg
        width={size}
        height={size}
        style={{ transform: "rotate(-90deg)", overflow: "visible" }}
      >
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="rgba(255, 255, 255, 0.12)"
          strokeWidth={strokeWidth}
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.8s linear, stroke 0.3s ease" }}
        />
      </svg>
      <span
        style={{
          position: "absolute",
          fontSize: "10px",
          fontWeight: 700,
          fontFamily: "ui-monospace, monospace",
          color: strokeColor,
          userSelect: "none",
        }}
      >
        {remaining}
      </span>
    </div>
  );
};
