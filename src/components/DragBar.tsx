// [ENC-B64::cnB0|Z2Ft|cm9k]
import React from "react";
import { invoke } from "@tauri-apps/api/core";

interface DragBarProps {
  className?: string;
}

export const DragBar: React.FC<DragBarProps> = ({ className = "" }) => {
  const handleMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.button === 0) {
      invoke("start_window_drag").catch(() => {});
    }
  };

  return (
    <div
      className={`window-drag-bar ${className}`}
      data-tauri-drag-region
      onMouseDown={handleMouseDown}
      role="presentation"
      title="AuthDesk"
      aria-label="Drag window"
    >
      <div className="drag-handle-pill" />
    </div>
  );
};
