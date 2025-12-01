
import React, { useEffect, useRef } from 'react';
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const skills = [
  { name: 'HTML', level: 90 },
  { name: 'CSS', level: 85 },
  { name: 'JavaScript', level: 80 },
  { name: 'MongoDB', level: 75 },
  { name: 'Xano', level: 85 },
  { name: 'AI', level: 70 },
  { name: 'Python', level: 65 },
  { name: 'Framer', level: 80 },
  { name: 'Git', level: 75 },
];

// Custom backgrounds for each skill
const skillBackgrounds = {
  'HTML': 'from-orange-400 to-red-500',
  'CSS': 'from-blue-400 to-blue-600',
  'JavaScript': 'from-yellow-300 to-yellow-500',
  'MongoDB': 'from-green-400 to-green-600',
  'Xano': 'from-purple-400 to-purple-600',
  'AI': 'from-indigo-400 to-indigo-600',
  'Python': 'from-blue-500 to-yellow-500',
  'Framer': 'from-pink-400 to-purple-500',
  'Git': 'from-red-400 to-orange-500',
};

const SkillsSection = () => {
  const skillsRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            const progressBars = document.querySelectorAll('.progress-bar');
            progressBars.forEach((bar, index) => {
              const htmlBar = bar as HTMLElement;
              setTimeout(() => {
                htmlBar.style.width = `${skills[index].level}%`;
                htmlBar.style.opacity = '1';
              }, index * 150);
            });
          }
        });
      },
      { threshold: 0.2 }
    );
    
    if (skillsRef.current) {
      observer.observe(skillsRef.current);
    }
    
    return () => {
      if (skillsRef.current) {
        observer.unobserve(skillsRef.current);
      }
    };
  }, []);

  return (
    <section id="skills" className="min-h-screen flex flex-col justify-center px-4 md:px-16">
      <div className="container mx-auto py-20">
        <h2 className="text-4xl md:text-6xl font-bold text-center mb-20 text-white tracking-tight" style={{ letterSpacing: '-0.03em' }}>
          Skills
        </h2>
        
        <div 
          ref={skillsRef}
          className="glass-effect p-10 rounded-3xl max-w-3xl mx-auto"
          style={{ WebkitBackdropFilter: 'blur(40px)' }}
        >
          {skills.map((skill, index) => (
            <div key={skill.name} className="mb-8">
              <div className="flex justify-between mb-3">
                <span className="text-base font-semibold tracking-tight">{skill.name}</span>
                <span className="text-sm text-gray-light/80 font-medium">{skill.level}%</span>
              </div>
              <div className="h-3 bg-muted rounded-full overflow-hidden">
                <div 
                  className="progress-bar h-full w-0 opacity-0 transition-all duration-1000 ease-out rounded-full bg-white"
                ></div>
              </div>
            </div>
          ))}
          
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-3 gap-3 mt-12">
            {skills.map((skill) => (
              <div 
                key={skill.name} 
                className="skill-badge relative overflow-hidden rounded-2xl p-4 h-20 flex items-center justify-center transform transition-all duration-300 hover:scale-105 bg-white/5 border border-white/10 hover:border-white hover:bg-white backdrop-blur-xl group"
                style={{ WebkitBackdropFilter: 'blur(40px)' }}
              >
                <span className="text-white font-semibold text-base z-10 group-hover:text-black tracking-tight transition-colors">
                  {skill.name}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default SkillsSection;
