import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { createPortal } from "react-dom";

import { formatBytes } from "../lib/format";
import type { ExtractedImage } from "../lib/images";

/**
 * Thumbnails for inline base64 images recovered from tool traffic. Every
 * image is a data: URL, so rendering never touches the network; clicking a
 * thumbnail opens a full-screen viewer with wheel zoom, drag panning and
 * arrow-key navigation.
 */
export function ImageAttachments({ images, ownerLabel }: { images: ExtractedImage[]; ownerLabel: string }) {
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const [broken, setBroken] = useState<Record<number, boolean>>({});

  if (images.length === 0) {
    return null;
  }

  return (
    <div className="mb-2">
      <ul className="flex flex-wrap gap-2" aria-label={`${ownerLabel}中的图片`}>
        {images.map((image, index) => (
          <li key={index}>
            {broken[index] ? (
              <span className="inline-flex h-24 items-center rounded-md border border-dashed bg-slate-50 px-3 text-xs text-muted-foreground">
                图片无法解码（{image.mediaType}，{formatBytes(image.bytes)}）
              </span>
            ) : (
              <button
                type="button"
                className="group block overflow-hidden rounded-md border bg-white shadow-sm transition-shadow hover:shadow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                title="点击放大查看"
                onClick={() => setOpenIndex(index)}
              >
                <img
                  src={image.src}
                  alt={`第 ${index + 1} 张图片（${image.mediaType}）`}
                  loading="lazy"
                  className="max-h-40 max-w-[16rem] cursor-zoom-in object-contain"
                  onError={() => setBroken((current) => ({ ...current, [index]: true }))}
                />
                <span className="block border-t bg-slate-50/80 px-2 py-1 text-left text-[11px] tabular-nums text-muted-foreground">
                  #{index + 1} · {image.mediaType} · {formatBytes(image.bytes)}
                </span>
              </button>
            )}
          </li>
        ))}
      </ul>
      {openIndex !== null && !broken[openIndex] ? (
        <ImageLightbox
          image={images[openIndex]}
          index={openIndex}
          count={images.length}
          onNavigate={(next) => setOpenIndex(((next % images.length) + images.length) % images.length)}
          onClose={() => setOpenIndex(null)}
        />
      ) : null}
    </div>
  );
}

interface ViewTransform {
  /** Scale on top of the fitted layout size (1 = fit to screen). */
  scale: number;
  tx: number;
  ty: number;
}

const fitTransform: ViewTransform = { scale: 1, tx: 0, ty: 0 };
const minScale = 0.2;
const maxScale = 40;

function ImageLightbox({
  image,
  index,
  count,
  onNavigate,
  onClose,
}: {
  image: ExtractedImage;
  index: number;
  count: number;
  onNavigate: (index: number) => void;
  onClose: () => void;
}) {
  const [transform, setTransform] = useState<ViewTransform>(fitTransform);
  // Multiplier that shows the bitmap at 100% of its natural pixels; measured
  // once the image lays out because the fitted size depends on the viewport.
  const [actualScale, setActualScale] = useState<number | null>(null);
  const surfaceRef = useRef<HTMLDivElement | null>(null);
  const imageRef = useRef<HTMLImageElement | null>(null);
  const drag = useRef<{ pointerId: number; lastX: number; lastY: number; moved: boolean } | null>(null);

  useEffect(() => {
    setTransform(fitTransform);
    setActualScale(null);
  }, [image.src]);

  // The viewer owns the screen while it is open: no page scrolling behind it.
  useEffect(() => {
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
    };
  }, []);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        onClose();
      } else if ((event.key === "ArrowRight" || event.key === "ArrowDown") && count > 1) {
        onNavigate(index + 1);
      } else if ((event.key === "ArrowLeft" || event.key === "ArrowUp") && count > 1) {
        onNavigate(index - 1);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [count, index, onClose, onNavigate]);

  // React registers wheel listeners passively, so zooming needs a native
  // non-passive listener to keep the event away from page scrolling.
  useEffect(() => {
    const surface = surfaceRef.current;
    if (!surface) {
      return;
    }
    function onWheel(event: WheelEvent) {
      event.preventDefault();
      const bounds = surface!.getBoundingClientRect();
      const pointerX = event.clientX - bounds.left - bounds.width / 2;
      const pointerY = event.clientY - bounds.top - bounds.height / 2;
      setTransform((current) => {
        const nextScale = Math.min(maxScale, Math.max(minScale, current.scale * Math.exp(-event.deltaY * 0.002)));
        if (nextScale === current.scale) {
          return current;
        }
        // Keep the image point under the cursor stationary while zooming.
        const ratio = nextScale / current.scale;
        return {
          scale: nextScale,
          tx: pointerX - (pointerX - current.tx) * ratio,
          ty: pointerY - (pointerY - current.ty) * ratio,
        };
      });
    }
    surface.addEventListener("wheel", onWheel, { passive: false });
    return () => surface.removeEventListener("wheel", onWheel);
  }, []);

  function onPointerDown(event: ReactPointerEvent<HTMLDivElement>) {
    if (event.button !== 0) {
      return;
    }
    drag.current = { pointerId: event.pointerId, lastX: event.clientX, lastY: event.clientY, moved: false };
    try {
      event.currentTarget.setPointerCapture(event.pointerId);
    } catch {
      // Panning still works without capture; it only loses the pointer when
      // it leaves the overlay, which covers the whole screen anyway.
    }
  }

  function onPointerMove(event: ReactPointerEvent<HTMLDivElement>) {
    const state = drag.current;
    if (!state || state.pointerId !== event.pointerId) {
      return;
    }
    const deltaX = event.clientX - state.lastX;
    const deltaY = event.clientY - state.lastY;
    state.lastX = event.clientX;
    state.lastY = event.clientY;
    if (Math.abs(deltaX) + Math.abs(deltaY) > 0) {
      state.moved = true;
      setTransform((current) => ({ ...current, tx: current.tx + deltaX, ty: current.ty + deltaY }));
    }
  }

  function onPointerUp(event: ReactPointerEvent<HTMLDivElement>) {
    if (drag.current?.pointerId === event.pointerId) {
      const moved = drag.current.moved;
      drag.current = null;
      // A clean click on the backdrop (not a drag, not on the image) closes.
      if (!moved && event.target === event.currentTarget) {
        onClose();
      }
    }
  }

  function measureActualScale(): number | null {
    const element = imageRef.current;
    if (!element || !element.naturalWidth || !element.clientWidth) {
      return null;
    }
    // clientWidth is the fitted layout size: CSS transforms do not affect it.
    return element.naturalWidth / element.clientWidth;
  }

  function toggleFitActual() {
    const factor = actualScale ?? measureActualScale() ?? 1;
    setTransform((current) => (Math.abs(current.scale - 1) < 0.01 ? { scale: factor, tx: 0, ty: 0 } : fitTransform));
  }

  const zoomPercent = actualScale ? Math.round((transform.scale / actualScale) * 100) : null;

  return createPortal(
    <div
      role="dialog"
      aria-modal="true"
      aria-label="图片放大查看"
      className="fixed inset-0 z-50 flex flex-col bg-slate-950/90 backdrop-blur-sm"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 text-slate-100">
        <p className="min-w-0 truncate text-xs text-slate-300">
          {count > 1 ? `第 ${index + 1} / ${count} 张 · ` : ""}
          {image.mediaType} · {formatBytes(image.bytes)}
          {zoomPercent !== null ? ` · ${zoomPercent}%` : ""}
        </p>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <LightboxButton onClick={() => setTransform(fitTransform)}>适应屏幕</LightboxButton>
          <LightboxButton
            onClick={() => {
              const factor = actualScale ?? measureActualScale();
              if (factor) {
                setTransform({ scale: factor, tx: 0, ty: 0 });
              }
            }}
          >
            原始大小
          </LightboxButton>
          <LightboxButton autoFocus onClick={onClose}>
            关闭（Esc）
          </LightboxButton>
        </div>
      </div>
      <div className="relative min-h-0 flex-1">
        <div
          ref={surfaceRef}
          className="flex h-full w-full cursor-grab touch-none select-none items-center justify-center overflow-hidden active:cursor-grabbing"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={() => {
            drag.current = null;
          }}
          onDoubleClick={toggleFitActual}
        >
          <img
            ref={imageRef}
            src={image.src}
            alt={`第 ${index + 1} 张图片放大视图`}
            draggable={false}
            className="max-h-full max-w-full object-contain"
            style={{
              transform: `translate(${transform.tx}px, ${transform.ty}px) scale(${transform.scale})`,
              transformOrigin: "center center",
            }}
            onLoad={() => setActualScale(measureActualScale())}
          />
        </div>
        {/* The arrows are siblings of the pan surface, not children: pointer
            capture on the surface must never swallow their clicks. */}
        {count > 1 ? (
          <>
            <NavigationArrow direction="previous" onClick={() => onNavigate(index - 1)} />
            <NavigationArrow direction="next" onClick={() => onNavigate(index + 1)} />
          </>
        ) : null}
      </div>
      <p className="px-4 pb-3 text-center text-[11px] text-slate-400">
        滚轮缩放 · 拖动平移 · 双击在适应屏幕与原始大小间切换{count > 1 ? " · ←/→ 切换图片" : ""} · Esc 关闭
      </p>
    </div>,
    document.body,
  );
}

function NavigationArrow({ direction, onClick }: { direction: "previous" | "next"; onClick: () => void }) {
  const isPrevious = direction === "previous";
  return (
    <button
      type="button"
      aria-label={isPrevious ? "上一张图片" : "下一张图片"}
      title={isPrevious ? "上一张（←）" : "下一张（→）"}
      className={`absolute top-1/2 z-10 grid h-12 w-12 -translate-y-1/2 place-items-center rounded-full border border-slate-600 bg-slate-800/80 text-slate-100 shadow-lg transition-colors hover:bg-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 ${
        isPrevious ? "left-4" : "right-4"
      }`}
      onPointerDown={(event) => event.stopPropagation()}
      onDoubleClick={(event) => event.stopPropagation()}
      onClick={onClick}
    >
      <svg aria-hidden="true" width="22" height="22" viewBox="0 0 24 24" fill="none">
        <path
          d={isPrevious ? "M14.5 5.5 8 12l6.5 6.5" : "M9.5 5.5 16 12l-6.5 6.5"}
          stroke="currentColor"
          strokeWidth="2.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </button>
  );
}

function LightboxButton({
  children,
  onClick,
  autoFocus = false,
}: {
  children: string;
  onClick: () => void;
  autoFocus?: boolean;
}) {
  return (
    <button
      type="button"
      autoFocus={autoFocus}
      className="rounded-md border border-slate-600 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-100 hover:bg-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300"
      onClick={onClick}
    >
      {children}
    </button>
  );
}
