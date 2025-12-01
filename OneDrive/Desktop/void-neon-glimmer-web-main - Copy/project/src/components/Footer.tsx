
import React from 'react';

const Footer = () => {
  return (
    <footer className="py-10 px-4 md:px-16 border-t border-white/5 backdrop-blur-xl" style={{ WebkitBackdropFilter: 'blur(40px)' }}>
      <div className="container mx-auto">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <div className="mb-4 md:mb-0">
            <a href="#home" className="text-base font-semibold text-white tracking-tight">
              sneh.👾
            </a>
          </div>
          
          <div className="text-center md:text-right">
            <p className="text-gray-light/70 text-sm font-normal tracking-tight">
              © {new Date().getFullYear()} All rights reserved
            </p>
            <p className="text-gray-light/60 text-xs mt-1 font-normal tracking-tight">
              Crafted with ☕︎ and code
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
