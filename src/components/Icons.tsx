// [ENC-B64::cnB0|Z2Ft|cm9k]
import React from "react";
import {
  Eye,
  EyeOff,
  Plus,
  Lock,
  Settings,
  Moon,
  Sun,
  Coffee,
  ArrowUp,
  ArrowDown,
  SquarePen,
  Trash2,
  X,
  AlertTriangle,
  Layout,
  Clock,
  Palette,
  Database,
  Shield,
  KeyRound,
  Check,
  Upload,
  Download,
  QrCode,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

export interface IconProps {
  size?: number;
  className?: string;
}

export const IconEye: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Eye size={size} strokeWidth={1.75} className={className} />
);

export const IconEyeOff: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <EyeOff size={size} strokeWidth={1.75} className={className} />
);

export const IconPlus: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Plus size={size} strokeWidth={1.75} className={className} />
);

export const IconLock: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Lock size={size} strokeWidth={1.75} className={className} />
);

export const IconSettings: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Settings size={size} strokeWidth={1.75} className={className} />
);

export const IconMoon: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Moon size={size} strokeWidth={1.75} className={className} />
);

export const IconSun: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Sun size={size} strokeWidth={1.75} className={className} />
);

export const IconCoffee: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Coffee size={size} strokeWidth={1.75} className={className} />
);

export const IconArrowUp: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <ArrowUp size={size} strokeWidth={1.75} className={className} />
);

export const IconArrowDown: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <ArrowDown size={size} strokeWidth={1.75} className={className} />
);

export const IconEdit: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <SquarePen size={size} strokeWidth={1.75} className={className} />
);

export const IconTrash: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <Trash2 size={size} strokeWidth={1.75} className={className} />
);

export const IconClose: React.FC<IconProps> = ({ size = 18, className = "" }) => (
  <X size={size} strokeWidth={1.75} className={className} />
);

export const IconAlertTriangle: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <AlertTriangle size={size} strokeWidth={1.75} className={className} />
);

export const IconLayout: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Layout size={size} strokeWidth={1.75} className={className} />
);

export const IconClock: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Clock size={size} strokeWidth={1.75} className={className} />
);

export const IconPalette: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Palette size={size} strokeWidth={1.75} className={className} />
);

export const IconDatabase: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Database size={size} strokeWidth={1.75} className={className} />
);

export const IconShield: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <Shield size={size} strokeWidth={1.75} className={className} />
);

export const IconKey: React.FC<IconProps> = ({ size = 20, className = "" }) => (
  <KeyRound size={size} strokeWidth={1.75} className={className} />
);

export const IconCheck: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <Check size={size} strokeWidth={1.75} className={className} />
);

export const IconUpload: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <Upload size={size} strokeWidth={1.75} className={className} />
);

export const IconDownload: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <Download size={size} strokeWidth={1.75} className={className} />
);

export const IconQrCode: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <QrCode size={size} strokeWidth={1.75} className={className} />
);

export const IconChevronLeft: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <ChevronLeft size={size} strokeWidth={1.75} className={className} />
);

export const IconChevronRight: React.FC<IconProps> = ({ size = 16, className = "" }) => (
  <ChevronRight size={size} strokeWidth={1.75} className={className} />
);

