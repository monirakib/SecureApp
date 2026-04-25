/* ======================================
   SECUREAPP - Particle & Animation Engine
   ====================================== */

(function() {
    'use strict';

    // ---- PARTICLE NETWORK ----
    const canvas = document.getElementById('particles-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let particles = [];
    let animId;
    let w, h;

    function resize() {
        w = canvas.width = window.innerWidth;
        h = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    const PARTICLE_COUNT = Math.min(80, Math.floor(window.innerWidth / 20));
    const CONNECT_DIST = 150;
    const MOUSE_DIST = 200;

    let mouse = { x: -9999, y: -9999 };
    document.addEventListener('mousemove', e => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });

    class Particle {
        constructor() {
            this.x = Math.random() * w;
            this.y = Math.random() * h;
            this.vx = (Math.random() - 0.5) * 0.5;
            this.vy = (Math.random() - 0.5) * 0.5;
            this.r = Math.random() * 1.5 + 0.5;
            // cyan or purple
            this.color = Math.random() > 0.5 ? '0, 240, 255' : '180, 0, 255';
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0 || this.x > w) this.vx *= -1;
            if (this.y < 0 || this.y > h) this.vy *= -1;

            // Mouse repulsion
            const dx = this.x - mouse.x;
            const dy = this.y - mouse.y;
            const dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < MOUSE_DIST) {
                const force = (MOUSE_DIST - dist) / MOUSE_DIST * 0.02;
                this.vx += (dx / dist) * force;
                this.vy += (dy / dist) * force;
            }

            // Damping
            this.vx *= 0.999;
            this.vy *= 0.999;
        }

        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${this.color}, 0.6)`;
            ctx.fill();

            // Glow
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.r * 3, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(${this.color}, 0.05)`;
            ctx.fill();
        }
    }

    // Create particles
    for (let i = 0; i < PARTICLE_COUNT; i++) {
        particles.push(new Particle());
    }

    function drawConnections() {
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < CONNECT_DIST) {
                    const alpha = (1 - dist / CONNECT_DIST) * 0.15;
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(0, 240, 255, ${alpha})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }
    }

    function animate() {
        ctx.clearRect(0, 0, w, h);
        particles.forEach(p => {
            p.update();
            p.draw();
        });
        drawConnections();
        animId = requestAnimationFrame(animate);
    }

    animate();

    // ---- INTERSECTION OBSERVER for float-in ----
    const observerOptions = { threshold: 0.1, rootMargin: '0px 0px -50px 0px' };
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('float-in-visible');
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    document.querySelectorAll('.observe-float').forEach(el => {
        observer.observe(el);
    });

    // ---- COUNTER ANIMATION ----
    document.querySelectorAll('.count-up').forEach(el => {
        const target = parseInt(el.textContent, 10);
        if (isNaN(target)) return;
        el.textContent = '0';
        let current = 0;
        const step = Math.max(1, Math.floor(target / 40));
        const interval = setInterval(() => {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(interval);
            }
            el.textContent = current;
        }, 30);
    });

    // ---- RANDOM HEX STREAM for decrypt effect ----
    document.querySelectorAll('.decrypt-text').forEach(el => {
        const original = el.textContent;
        const chars = '0123456789ABCDEF';
        let iterations = 0;

        const interval = setInterval(() => {
            el.textContent = original.split('').map((char, i) => {
                if (i < iterations) return original[i];
                return chars[Math.floor(Math.random() * chars.length)];
            }).join('');

            iterations += 1 / 2;
            if (iterations >= original.length) {
                clearInterval(interval);
                el.textContent = original;
            }
        }, 40);
    });

    // ---- NAVBAR ACTIVE HIGHLIGHT ----
    const currentPath = window.location.pathname;
    document.querySelectorAll('.navbar .nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.style.color = 'var(--cyan)';
            link.style.textShadow = '0 0 10px rgba(0, 240, 255, 0.4)';
        }
    });

})();
