
import React from 'react';
import { useIsMobile } from '../hooks/use-mobile';

const skills = [
  'HTML', 'CSS', 'JavaScript', 'React', 'NextJS', 'NodeJS', 'GraphQL',
  'MongoDB', 'MySQL', 'AI', 'MLOps', 'Arduino', 'Python', 'Panda', 'NumPy', 'PyTorch',
  'TensorFlow', 'Embedded Systems', 'Raspberry Pi', 'GitHub', 'CI/CD',
  'Docker', 'Kubernetes', 'OpenCV', 'NGINX', 'Automation', 'Robotics',
  'Hackathons', 'Voice Drones', 'Git', 'UI Design'
];

const AboutSection = () => {
  const isMobile = useIsMobile();

  return (
    <section id="about" className="min-h-screen flex flex-col justify-center px-4 md:px-16">
      <div className="container mx-auto py-20">
        <h2 className="text-4xl md:text-6xl font-bold text-center mb-20 text-white tracking-tight" style={{ letterSpacing: '-0.03em' }}>
          About Me
        </h2>
        
        <div className="grid md:grid-cols-2 gap-12 items-center">
          <div className="glass-effect p-10 rounded-3xl" style={{ WebkitBackdropFilter: 'blur(40px)' }}>
            <p className="text-base md:text-lg text-gray-light/90 leading-relaxed font-normal tracking-tight" style={{ letterSpacing: '-0.01em' }}>
              Right now at my 20's I work at the crossroads of AI/ML, robotics, and automation turning loose ideas into systems that actually move, react, and make decisions. Whether it’s AI agents, autonomous pipelines, or voice-controlled drones, I like building things that don’t just sit in a repo but come alive when you put them into the real world.
            </p>
            <p className="text-base md:text-lg text-gray-light/90 leading-relaxed mt-6 font-normal tracking-tight" style={{ letterSpacing: '-0.01em' }}>
              Hackathons are my testing ground pressure-cooker sprints where half-baked ideas either sink or swim. I’ve learned to trust the work, cut the noise, and ship fast. When something breaks, I don’t patch it; I rebuild it until it doesn’t flinch.
            </p>
            <p className="text-base md:text-lg text-gray-light/90 leading-relaxed mt-6 font-normal tracking-tight" style={{ letterSpacing: '-0.01em' }}>
              I’m currently sharpening my skills in machine learning, intelligent automation, and scalable backend design. I prefer projects where the stakes are real and the learning curve is steep because that’s where you figure out if you’re just tinkering or actually building something worth its weight.
            </p>
            <p className="text-base md:text-lg text-gray-light/90 leading-relaxed mt-6 font-normal tracking-tight" style={{ letterSpacing: '-0.01em' }}>
              I work like someone keeping an eye on the long game, always building the next tool in my arsenal step by step, brick by brick.
            </p>
          </div>
          
          <div className="flex flex-wrap justify-center gap-4">
            {skills.map((skill, index) => (
              <div
                key={skill}
                className="skill-badge-simple hover:scale-110 hover:-translate-y-1 transition-all duration-300"
              >
                {skill}
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default AboutSection;
