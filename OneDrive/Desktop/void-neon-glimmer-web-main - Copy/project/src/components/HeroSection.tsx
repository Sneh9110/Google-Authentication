
import React from 'react';
import { useIsMobile } from '../hooks/use-mobile';

const HeroSection = () => {
  const isMobile = useIsMobile();

  return (
    <section id="home" className="min-h-screen flex flex-col justify-center px-4 md:px-16">
      <div className="container mx-auto my-8 md:my-16 pt-20">
        <div className="grid md:grid-cols-2 gap-20 md:gap-32 items-center">
          <div 
            className="w-full flex justify-center md:justify-end order-1 md:order-1"
          >
            <div className="relative w-64 h-64 sm:w-80 sm:h-80 md:w-96 md:h-96">
              {/* Photo in circular shape */}
              <div className="relative w-full h-full rounded-full overflow-hidden">
                <img 
                  src="/profile.jpg" 
                  alt="Profile" 
                  className="w-full h-full object-cover animate-float"
                  style={{ 
                    filter: 'contrast(1.05) brightness(1.05)',
                  }}
                />
              </div>
              
              {/* Subtle shadow for depth */}
              <div className="absolute inset-0 rounded-full shadow-2xl" style={{ boxShadow: '0 25px 50px rgba(0, 0, 0, 0.5)' }}></div>
            </div>
          </div>
          
          <div className="text-center md:text-left order-2 md:order-2">
            <h1 className="text-4xl md:text-6xl lg:text-7xl font-bold mb-6 tracking-tight leading-tight" style={{ letterSpacing: '-0.04em' }}>
              <span className="inline-block overflow-hidden whitespace-nowrap border-r-4 border-white w-0 animate-typewriter">
                Hi, I'm Sneh
              </span>
            </h1>
            
            <p className="text-lg md:text-xl text-gray-light/80 mb-12 font-normal tracking-tight" style={{ letterSpacing: '-0.01em' }}>
              IT Engineer • MLOps • AI • Robotics & Autonomous Systems
            </p>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center md:justify-start">
              <a href="#projects" className="neon-button">
                <span>View Projects</span>
              </a>
              <a href="#contact" className="neon-button">
                <span>Hire Me</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
