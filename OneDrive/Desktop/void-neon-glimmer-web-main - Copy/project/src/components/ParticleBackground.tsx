
import React, { useEffect, useRef } from 'react';
import { useIsMobile } from '../hooks/use-mobile';

const ParticleBackground = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const mousePosition = useRef({ x: 0, y: 0 });
  const isMobile = useIsMobile();
  
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d', { alpha: false });
    if (!ctx) return;
    
    let width = window.innerWidth;
    let height = window.innerHeight;
    let particles: Array<{
      x: number;
      y: number;
      radius: number;
      color: string;
      speedX: number;
      speedY: number;
      originalX: number;
      originalY: number;
    }> = [];

    const resizeCanvas = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width;
      canvas.height = height;
      initParticles();
    };

    const updateMousePosition = (e: MouseEvent) => {
      mousePosition.current = {
        x: e.clientX,
        y: e.clientY
      };
    };

    // For touch devices
    const updateTouchPosition = (e: TouchEvent) => {
      if (e.touches.length > 0) {
        mousePosition.current = {
          x: e.touches[0].clientX,
          y: e.touches[0].clientY
        };
      }
    };

    const initParticles = () => {
      particles = [];
      // Drastically reduced particle count for performance
      const deviceMultiplier = isMobile ? 0.2 : 0.4;
      const particleCount = Math.min(Math.floor((width * height / 20000) * deviceMultiplier), 40);
      
      for (let i = 0; i < particleCount; i++) {
        const radius = Math.random() * 2 + 0.5;
        const x = Math.random() * width;
        const y = Math.random() * height;
        
        // Minimalist white/gray colors
        const colors = [
          'rgba(255, 255, 255, 0.6)',  // White
          'rgba(255, 255, 255, 0.4)',  // Light white
          'rgba(180, 180, 180, 0.5)',  // Gray
          'rgba(200, 200, 200, 0.5)'   // Light gray
        ];
        const color = colors[Math.floor(Math.random() * colors.length)];
        
        particles.push({
          x,
          y,
          radius,
          color,
          speedX: Math.random() * 0.5 - 0.25,
          speedY: Math.random() * 0.5 - 0.25,
          originalX: x,
          originalY: y
        });
      }
    };

    const drawParticles = () => {
      ctx.clearRect(0, 0, width, height);
      
      // Pure black background
      ctx.fillStyle = 'rgba(0, 0, 0, 1)';
      ctx.fillRect(0, 0, width, height);
      
      // Draw minimal starfield in background
      for (let i = 0; i < 15; i++) {
        const starSize = Math.random() * 0.8;
        const starX = Math.random() * width;
        const starY = Math.random() * height;
        const opacity = Math.random() * 0.3 + 0.1;
        
        ctx.beginPath();
        ctx.arc(starX, starY, starSize, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255, 255, 255, ${opacity})`;
        ctx.fill();
      }
      
      particles.forEach(particle => {
        // Move particle
        particle.x += particle.speedX;
        particle.y += particle.speedY;
        
        // Boundary check
        if (particle.x < 0 || particle.x > width) particle.speedX *= -1;
        if (particle.y < 0 || particle.y > height) particle.speedY *= -1;
        
        // Simplified mouse interaction
        const dx = mousePosition.current.x - particle.x;
        const dy = mousePosition.current.y - particle.y;
        const distance = dx * dx + dy * dy; // Skip sqrt for performance
        const interactionRadius = isMobile ? 6400 : 22500; // squared values
        
        if (distance < interactionRadius) {
          const force = 0.5;
          particle.x -= (dx / 100) * force;
          particle.y -= (dy / 100) * force;
        } else {
          // Gradually return to original position
          particle.x += (particle.originalX - particle.x) * 0.005;
          particle.y += (particle.originalY - particle.y) * 0.005;
        }
        
        // Draw particle (simplified)
        ctx.beginPath();
        ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
        ctx.fillStyle = particle.color;
        ctx.fill();
      });
      
      // Connect nearby particles with lines (optimized)
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const distance = Math.sqrt(dx * dx + dy * dy);
          
          // Reduced connection distance for better performance
          const connectionDistance = isMobile ? 60 : 100;
          
          if (distance < connectionDistance) {
            // Calculate gradient color based on particle colors
            const gradient = ctx.createLinearGradient(
              particles[i].x, particles[i].y, 
              particles[j].x, particles[j].y
            );
            
            gradient.addColorStop(0, particles[i].color.replace('0.8', `${(connectionDistance - distance) / connectionDistance * 0.4}`));
            gradient.addColorStop(1, particles[j].color.replace('0.8', `${(connectionDistance - distance) / connectionDistance * 0.4}`));
            
            ctx.beginPath();
            ctx.strokeStyle = gradient;
            ctx.lineWidth = Math.max(0.1, (connectionDistance - distance) / connectionDistance);
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }
      
      requestAnimationFrame(drawParticles);
    };

    // Initialize and start animation
    resizeCanvas();
    drawParticles();
    
    window.addEventListener('resize', resizeCanvas);
    window.addEventListener('mousemove', updateMousePosition);
    window.addEventListener('touchmove', updateTouchPosition);
    window.addEventListener('touchstart', updateTouchPosition);
    
    return () => {
      window.removeEventListener('resize', resizeCanvas);
      window.removeEventListener('mousemove', updateMousePosition);
      window.removeEventListener('touchmove', updateTouchPosition);
      window.removeEventListener('touchstart', updateTouchPosition);
    };
  }, [isMobile]);

  return (
    <canvas 
      ref={canvasRef} 
      className="fixed top-0 left-0 w-full h-full -z-10"
    />
  );
};

export default ParticleBackground;
