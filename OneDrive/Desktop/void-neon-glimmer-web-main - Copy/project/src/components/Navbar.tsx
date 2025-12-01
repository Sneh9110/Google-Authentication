
import React, { useState, useEffect } from 'react';

const Navbar = () => {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      const isScrolled = window.scrollY > 10;
      if (isScrolled !== scrolled) {
        setScrolled(isScrolled);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [scrolled]);

  const navLinks = [
    { name: 'Home', href: '#home' },
    { name: 'About', href: '#about' },
    { name: 'Projects', href: '#projects' },
    { name: 'Photography', href: '#photography' },
    { name: 'Skills', href: '#skills' },
    { name: 'Contact', href: '#contact' }
  ];

  return (
    <header className="fixed top-8 left-0 right-0 z-50 flex justify-center px-4">
      <nav 
        className={`transition-all duration-300 ${
          scrolled 
            ? 'bg-black/80 backdrop-blur-2xl border border-white/10 shadow-2xl' 
            : 'bg-black/60 backdrop-blur-xl border border-white/5'
        } rounded-full px-6 py-3.5 flex items-center gap-8`}
        style={{ WebkitBackdropFilter: 'blur(40px)' }}
      >
        <a href="#home" className="text-lg font-semibold text-white hover:text-gray-light transition-colors tracking-tight">
          sneh.👾
        </a>
        <div className="hidden md:flex items-center gap-7">
          {navLinks.map((link) => (
            <a 
              key={link.name} 
              href={link.href} 
              className="nav-link"
            >
              {link.name}
            </a>
          ))}
        </div>
        <div className="md:hidden">
          <button className="text-white">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="3" y1="12" x2="21" y2="12"></line>
              <line x1="3" y1="6" x2="21" y2="6"></line>
              <line x1="3" y1="18" x2="21" y2="18"></line>
            </svg>
          </button>
        </div>
      </nav>
    </header>
  );
};

export default Navbar;
