
import React, { useEffect } from 'react';
import Navbar from '../components/Navbar';
import ParticleBackground from '../components/ParticleBackground';
import CustomCursor from '../components/CustomCursor';
import HeroSection from '../components/HeroSection';
import AboutSection from '../components/AboutSection';
import ProjectsSection from '../components/ProjectsSection';
import PhotographySection from '../components/PhotographySection';
import SkillsSection from '../components/SkillsSection';
import ContactSection from '../components/ContactSection';
import Footer from '../components/Footer';
import { useIsMobile } from '../hooks/use-mobile';

const Index = () => {
  const isMobile = useIsMobile();

  useEffect(() => {
    // Update document title
    document.title = "sneh.👾 | Portfolio";
    
    // Only disable default cursor on desktop devices
    if (!isMobile) {
      document.body.style.cursor = 'none';
    } else {
      document.body.style.cursor = 'default';
    }
    
    return () => {
      document.body.style.cursor = 'default';
    };
  }, [isMobile]);

  return (
    <main className="relative overflow-x-hidden min-h-screen bg-black text-white">
      {!isMobile && <CustomCursor />}
      <ParticleBackground />
      <Navbar />
      
      <div className="space-y-24 md:space-y-32 pb-16">
        <HeroSection />
        <AboutSection />
        <ProjectsSection />
        <PhotographySection />
        <SkillsSection />
        <ContactSection />
      </div>
      
      <Footer />
    </main>
  );
};

export default Index;
