
import React, { useEffect } from 'react';

// Sample photography images (replace with your actual images)
const photos = [
  {
    id: 1,
    url: 'https://images.unsplash.com/photo-1559827291-72ee739d0d9a',
    title: 'Urban Geometry'
  },
  {
    id: 2,
    url: 'https://images.unsplash.com/photo-1533279443086-d1c19a186416',
    title: 'Neon City'
  },
  {
    id: 3,
    url: 'https://images.unsplash.com/photo-1492724724894-7464c27d0ceb',
    title: 'Architectural Detail'
  },
  {
    id: 4,
    url: 'https://images.unsplash.com/photo-1520209759809-a9bcb6cb3241',
    title: 'Night Street'
  },
  {
    id: 5,
    url: 'https://images.unsplash.com/photo-1515091943-9d5c0ad475af',
    title: 'Tech Abstract'
  },
  {
    id: 6,
    url: 'https://images.unsplash.com/photo-1588412079929-7b9225571e0b',
    title: 'Digital World'
  }
];

const PhotographySection = () => {
  useEffect(() => {
    // Apply random floating animation to photo cards
    const photoCards = document.querySelectorAll('.photo-card');
    
    photoCards.forEach(card => {
      const htmlCard = card as HTMLElement;
      
      // Random starting position and animation duration
      const startX = Math.random() * 20 - 10; // -10px to 10px
      const startY = Math.random() * 20 - 10; // -10px to 10px
      const duration = 3 + Math.random() * 5; // 3s to 8s
      
      htmlCard.style.animation = `float ${duration}s ease-in-out infinite`;
      htmlCard.style.transform = `translate(${startX}px, ${startY}px)`;
    });
  }, []);

  return (
    <section id="photography" className="min-h-screen flex flex-col justify-center px-4 md:px-16">
      <div className="container mx-auto py-20">
        <h2 className="text-4xl md:text-6xl font-bold text-center mb-20 tracking-tight" style={{ letterSpacing: '-0.03em' }}>
          <span className="text-white">Through My Lens 📸</span>
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {photos.map((photo) => (
            <div 
              key={photo.id} 
              className="photo-card overflow-hidden h-64 md:h-80"
            >
              <div className="relative w-full h-full group cursor-pointer">
                <img 
                  src={photo.url} 
                  alt={photo.title} 
                  className="w-full h-full object-cover transition-all duration-500 group-hover:scale-110 grayscale"
                />
                <div className="absolute inset-0 bg-black/70 backdrop-blur-md opacity-0 group-hover:opacity-100 transition-opacity duration-300 flex items-end justify-center p-6" style={{ WebkitBackdropFilter: 'blur(8px)' }}>
                  <h3 className="text-white text-lg font-semibold tracking-tight">
                    {photo.title}
                  </h3>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default PhotographySection;
