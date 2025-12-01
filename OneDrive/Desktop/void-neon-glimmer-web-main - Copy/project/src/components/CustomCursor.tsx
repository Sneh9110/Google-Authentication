
import React, { useEffect, useRef } from 'react';
import { useIsMobile } from '../hooks/use-mobile';

const CustomCursor = () => {
  const cursorRef = useRef<HTMLDivElement>(null);
  const cursorDotRef = useRef<HTMLDivElement>(null);
  const isMobile = useIsMobile();
  
  useEffect(() => {
    // Don't implement custom cursor on mobile devices
    if (isMobile) return;
    
    const cursor = cursorRef.current;
    const cursorDot = cursorDotRef.current;
    
    if (!cursor || !cursorDot) return;
    
    let animationFrameId: number;
    let mouseX = 0;
    let mouseY = 0;
    
    const onMouseMove = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
      
      // Check if hovering over interactive elements
      const target = e.target as HTMLElement;
      const isInteractive = target.tagName === 'BUTTON' || 
                           target.tagName === 'A' || 
                           target.closest('button') || 
                           target.closest('a');
      
      if (isInteractive) {
        cursor.classList.add('cursor-hover');
        cursorDot.classList.add('cursor-dot-hover');
      } else {
        cursor.classList.remove('cursor-hover');
        cursorDot.classList.remove('cursor-dot-hover');
      }
    };
    
    const updateCursorPosition = () => {
      if (cursor && cursorDot) {
        cursor.style.transform = `translate(${mouseX}px, ${mouseY}px) translate(-50%, -50%)`;
        cursorDot.style.transform = `translate(${mouseX}px, ${mouseY}px) translate(-50%, -50%)`;
      }
      animationFrameId = requestAnimationFrame(updateCursorPosition);
    };
    
    document.addEventListener('mousemove', onMouseMove, { passive: true });
    animationFrameId = requestAnimationFrame(updateCursorPosition);
    
    return () => {
      document.removeEventListener('mousemove', onMouseMove);
      cancelAnimationFrame(animationFrameId);
    };
  }, [isMobile]);
  
  // Don't render cursor on mobile
  if (isMobile) return null;
  
  return (
    <>
      <div 
        ref={cursorRef}
        className="custom-cursor fixed pointer-events-none z-[999]"
        style={{ left: 0, top: 0 }}
      />
      <div
        ref={cursorDotRef}
        className="cursor-dot fixed pointer-events-none z-[999]"
        style={{ left: 0, top: 0 }}
      />
    </>
  );
};

export default CustomCursor;
