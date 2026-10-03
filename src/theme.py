"""
Cybersecurity Glassmorphism Theme & Style Injection Module.
Provides centralized design tokens, custom CSS variables, glassmorphism cards, glow utilities, and keyframes.
"""

import textwrap
import streamlit as st


def inject_theme():
    """
    Injects global CSS custom properties, fonts, glassmorphic card classes,
    glow borders, button gradients, step spinners, and animations for a cohesive dark cybersecurity aesthetic.
    """
    st.markdown(
        textwrap.dedent(
            """
            <style>
        /* -------------------------------------------------------------------------- */
        /* 1. TYPOGRAPHY & FONT IMPORTS                                               */
        /* -------------------------------------------------------------------------- */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

        /* -------------------------------------------------------------------------- */
        /* 2. CSS CUSTOM PROPERTIES (DESIGN TOKENS)                                   */
        /* -------------------------------------------------------------------------- */
        :root {
            /* Backgrounds */
            --bg-primary: #080C16;
            --bg-secondary: #0F172A;
            --bg-card: rgba(19, 28, 46, 0.72);
            --bg-card-hover: rgba(26, 38, 62, 0.85);
            --bg-glass: rgba(15, 23, 42, 0.65);
            
            /* Borders & Shadows */
            --border-card: rgba(255, 255, 255, 0.08);
            --border-card-hover: rgba(0, 210, 255, 0.4);
            --shadow-glass: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            --shadow-glow-cyan: 0 0 20px rgba(0, 210, 255, 0.35);
            --shadow-glow-purple: 0 0 20px rgba(139, 92, 246, 0.35);
            --shadow-glow-red: 0 0 20px rgba(239, 68, 68, 0.35);
            --shadow-glow-green: 0 0 20px rgba(16, 185, 129, 0.35);

            /* Accents */
            --accent-cyan: #00D2FF;
            --accent-cyan-dim: rgba(0, 210, 255, 0.15);
            --accent-purple: #8B5CF6;
            --accent-indigo: #6366F1;
            
            /* Status / Threat Colors */
            --warning-red: #EF4444;
            --warning-red-dim: rgba(239, 68, 68, 0.18);
            --warning-orange: #F59E0B;
            --safe-teal: #06B6D4;
            --safe-green: #10B981;
            --safe-green-dim: rgba(16, 185, 129, 0.18);

            /* Text Tokens */
            --text-primary: #F8FAFC;
            --text-secondary: #94A3B8;
            --text-muted: #64748B;

            /* Font Families */
            --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
        }

        /* -------------------------------------------------------------------------- */
        /* 3. GLOBAL HTML & APP RESETS & BASE ANIMATED GRADIENT                       */
        /* -------------------------------------------------------------------------- */
        html, body, [class*="css"] {
            font-family: var(--font-sans);
            color: var(--text-primary);
        }

        @keyframes bgGradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        .stApp {
            background: linear-gradient(135deg, #070B14 0%, #0B1120 35%, #0F172A 70%, #080D18 100%);
            background-size: 250% 250%;
            animation: bgGradientShift 75s ease infinite;
            color: var(--text-primary);
        }

        /* Sidebar Styling */
        [data-testid="stSidebar"] {
            background-color: var(--bg-secondary) !important;
            border-right: 1px solid var(--border-card) !important;
            position: relative;
            z-index: 2 !important;
        }

        [data-testid="stAppViewContainer"] > .main {
            position: relative;
            z-index: 1;
        }

        /* -------------------------------------------------------------------------- */
        /* 4. KEYFRAME ANIMATIONS & AMBIENT ORB DRIFT                                 */
        /* -------------------------------------------------------------------------- */
        @keyframes float {
            0% { transform: translateY(0px); }
            50% { transform: translateY(-6px); }
            100% { transform: translateY(0px); }
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.85; transform: scale(1.03); }
        }

        @keyframes rotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes glow {
            0%, 100% { box-shadow: 0 0 12px rgba(0, 210, 255, 0.25); }
            50% { box-shadow: 0 0 28px rgba(0, 210, 255, 0.55); }
        }

        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translate3d(0, 16px, 0);
            }
            to {
                opacity: 1;
                transform: translate3d(0, 0, 0);
            }
        }

        /* Ambient Orb Keyframes (Pure CSS Transform Drift, No JS Loops) */
        @keyframes orbDrift1 {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(80px, 60px, 0) scale(1.1); }
            100% { transform: translate3d(40px, 120px, 0) scale(0.95); }
        }

        @keyframes orbDrift2 {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(-90px, 70px, 0) scale(1.08); }
            100% { transform: translate3d(-40px, 130px, 0) scale(0.92); }
        }

        @keyframes orbDrift3 {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(60px, -50px, 0) scale(1.12); }
            100% { transform: translate3d(110px, 35px, 0) scale(0.96); }
        }

        @keyframes orbDrift4 {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(-70px, -60px, 0) scale(1.09); }
            100% { transform: translate3d(-110px, -25px, 0) scale(0.94); }
        }

        @keyframes orbDrift5 {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(85px, -70px, 0) scale(1.12); }
            100% { transform: translate3d(45px, -110px, 0) scale(0.92); }
        }

        @keyframes orbDrift6 {
            0% { transform: translate3d(0, 0, 0) scale(1); }
            50% { transform: translate3d(-55px, 80px, 0) scale(1.08); }
            100% { transform: translate3d(-95px, 45px, 0) scale(0.95); }
        }

        /* Fixed Ambient Background, Subtle Grid Texture, Soft Blurred Orbs, Streams & Particles */
        @keyframes gridDrift {
            0% { background-position: 0px 0px, 0px 0px, 0px 0px; }
            100% { background-position: 64px 64px, 128px 128px, 128px 128px; }
        }

        @keyframes streamDrift1 {
            0% { transform: translate3d(-300px, -60px, 0) rotate(22deg); opacity: 0; }
            15% { opacity: 0.22; }
            85% { opacity: 0.22; }
            100% { transform: translate3d(115vw, 55vh, 0) rotate(22deg); opacity: 0; }
        }

        @keyframes streamDrift2 {
            0% { transform: translate3d(115vw, 95vh, 0) rotate(-24deg); opacity: 0; }
            18% { opacity: 0.20; }
            82% { opacity: 0.20; }
            100% { transform: translate3d(-320px, 35vh, 0) rotate(-24deg); opacity: 0; }
        }

        @keyframes streamDrift3 {
            0% { transform: translate3d(-350px, 48vh, 0) rotate(8deg); opacity: 0; }
            12% { opacity: 0.18; }
            88% { opacity: 0.18; }
            100% { transform: translate3d(110vw, 68vh, 0) rotate(8deg); opacity: 0; }
        }

        /* Inward Particle Drift Animations (Seamless Fade Reset) */
        @keyframes particleDrift1 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.42; transform: translate3d(6vw, 5vh, 0) scale(1); }
            80% { opacity: 0.36; transform: translate3d(24vw, 20vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(30vw, 25vh, 0) scale(0.6); }
        }
        @keyframes particleDrift2 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.38; transform: translate3d(1vw, 6vh, 0) scale(1); }
            80% { opacity: 0.32; transform: translate3d(4vw, 24vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(5vw, 30vh, 0) scale(0.6); }
        }
        @keyframes particleDrift3 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.40; transform: translate3d(-5vw, 5vh, 0) scale(1); }
            80% { opacity: 0.35; transform: translate3d(-20vw, 20vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(-26vw, 25vh, 0) scale(0.6); }
        }
        @keyframes particleDrift4 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.35; transform: translate3d(-6vw, 1vh, 0) scale(1); }
            80% { opacity: 0.30; transform: translate3d(-24vw, 4vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(-30vw, 5vh, 0) scale(0.6); }
        }
        @keyframes particleDrift5 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.40; transform: translate3d(-5vw, -5vh, 0) scale(1); }
            80% { opacity: 0.34; transform: translate3d(-22vw, -20vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(-28vw, -25vh, 0) scale(0.6); }
        }
        @keyframes particleDrift6 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.38; transform: translate3d(-1vw, -6vh, 0) scale(1); }
            80% { opacity: 0.32; transform: translate3d(-4vw, -24vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(-5vw, -30vh, 0) scale(0.6); }
        }
        @keyframes particleDrift7 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.42; transform: translate3d(5vw, -5vh, 0) scale(1); }
            80% { opacity: 0.35; transform: translate3d(22vw, -20vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(28vw, -25vh, 0) scale(0.6); }
        }
        @keyframes particleDrift8 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.36; transform: translate3d(6vw, 1vh, 0) scale(1); }
            80% { opacity: 0.30; transform: translate3d(24vw, 4vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(30vw, 5vh, 0) scale(0.6); }
        }
        @keyframes particleDrift9 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.40; transform: translate3d(4vw, 4vh, 0) scale(1); }
            80% { opacity: 0.34; transform: translate3d(16vw, 15vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(20vw, 19vh, 0) scale(0.6); }
        }
        @keyframes particleDrift10 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.38; transform: translate3d(-4vw, 4vh, 0) scale(1); }
            80% { opacity: 0.32; transform: translate3d(-15vw, 14vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(-19vw, 18vh, 0) scale(0.6); }
        }
        @keyframes particleDrift11 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.40; transform: translate3d(-4vw, -4vh, 0) scale(1); }
            80% { opacity: 0.35; transform: translate3d(-16vw, -15vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(-20vw, -19vh, 0) scale(0.6); }
        }
        @keyframes particleDrift12 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.36; transform: translate3d(4vw, -4vh, 0) scale(1); }
            80% { opacity: 0.30; transform: translate3d(15vw, -14vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(19vw, -18vh, 0) scale(0.6); }
        }
        @keyframes particleDrift13 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.38; transform: translate3d(-3vw, 5vh, 0) scale(1); }
            80% { opacity: 0.32; transform: translate3d(-12vw, 22vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(-15vw, 28vh, 0) scale(0.6); }
        }
        @keyframes particleDrift14 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.36; transform: translate3d(3vw, -5vh, 0) scale(1); }
            80% { opacity: 0.30; transform: translate3d(11vw, -20vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(14vw, -26vh, 0) scale(0.6); }
        }
        @keyframes particleDrift15 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.40; transform: translate3d(5vw, -3vh, 0) scale(1); }
            80% { opacity: 0.34; transform: translate3d(20vw, -11vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(25vw, -14vh, 0) scale(0.6); }
        }
        @keyframes particleDrift16 {
            0% { opacity: 0; transform: translate3d(0, 0, 0) scale(0.7); }
            20% { opacity: 0.38; transform: translate3d(-5vw, 3vh, 0) scale(1); }
            80% { opacity: 0.32; transform: translate3d(-20vw, 12vh, 0) scale(1); }
            100% { opacity: 0; transform: translate3d(-25vw, 15vh, 0) scale(0.6); }
        }

        .sentinel-ambient-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            overflow: hidden;
            pointer-events: none !important;
            z-index: 0;
        }

        .sentinel-ambient-grid {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                radial-gradient(rgba(0, 210, 255, 0.10) 1px, transparent 1px),
                linear-gradient(to right, rgba(255, 255, 255, 0.02) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
            background-size: 32px 32px, 64px 64px, 64px 64px;
            opacity: 0.045;
            pointer-events: none !important;
            z-index: -1;
            animation: gridDrift 75s linear infinite;
        }

        .sentinel-orb {
            position: absolute;
            border-radius: 50%;
            filter: blur(85px);
            -webkit-filter: blur(85px);
            pointer-events: none !important;
            opacity: 0.14;
            will-change: transform;
        }

        .sentinel-orb-1 {
            top: -10%;
            left: -5%;
            width: 500px;
            height: 500px;
            background: radial-gradient(circle, var(--accent-cyan) 0%, rgba(0, 210, 255, 0.2) 60%, transparent 80%);
            animation: orbDrift1 42s ease-in-out infinite alternate;
        }

        .sentinel-orb-2 {
            top: 5%;
            right: -8%;
            width: 550px;
            height: 550px;
            background: radial-gradient(circle, var(--accent-purple) 0%, rgba(139, 92, 246, 0.2) 60%, transparent 80%);
            animation: orbDrift2 54s ease-in-out infinite alternate;
        }

        .sentinel-orb-3 {
            top: 45%;
            left: 12%;
            width: 420px;
            height: 420px;
            background: radial-gradient(circle, #6366F1 0%, rgba(99, 102, 241, 0.18) 60%, transparent 80%);
            animation: orbDrift3 36s ease-in-out infinite alternate;
        }

        .sentinel-orb-4 {
            bottom: -15%;
            right: 15%;
            width: 520px;
            height: 520px;
            background: radial-gradient(circle, #06B6D4 0%, rgba(6, 182, 212, 0.18) 60%, transparent 80%);
            animation: orbDrift4 46s ease-in-out infinite alternate;
        }

        .sentinel-orb-5 {
            bottom: 12%;
            left: -8%;
            width: 460px;
            height: 460px;
            background: radial-gradient(circle, #7C3AED 0%, rgba(124, 58, 237, 0.16) 60%, transparent 80%);
            animation: orbDrift5 60s ease-in-out infinite alternate;
        }

        .sentinel-orb-6 {
            top: 32%;
            right: 22%;
            width: 380px;
            height: 380px;
            background: radial-gradient(circle, #38BDF8 0%, rgba(56, 189, 248, 0.14) 60%, transparent 80%);
            animation: orbDrift6 32s ease-in-out infinite alternate;
        }

        /* Ambient Data Stream Lines (2-4 Streams, Cap: 3) */
        .sentinel-data-stream {
            position: absolute;
            pointer-events: none !important;
            border-radius: 999px;
            filter: blur(1.5px);
            -webkit-filter: blur(1.5px);
            will-change: transform, opacity;
        }

        .sentinel-data-stream-1 {
            top: 0;
            left: 0;
            width: 220px;
            height: 2px;
            background: linear-gradient(90deg, transparent 0%, rgba(0, 210, 255, 0.7) 45%, rgba(99, 102, 241, 0.6) 70%, transparent 100%);
            box-shadow: 0 0 10px rgba(0, 210, 255, 0.4);
            animation: streamDrift1 45s linear infinite;
            animation-delay: -12s;
        }

        .sentinel-data-stream-2 {
            top: 0;
            left: 0;
            width: 260px;
            height: 2px;
            background: linear-gradient(90deg, transparent 0%, rgba(139, 92, 246, 0.65) 40%, rgba(6, 182, 212, 0.6) 75%, transparent 100%);
            box-shadow: 0 0 10px rgba(139, 92, 246, 0.35);
            animation: streamDrift2 58s linear infinite;
            animation-delay: -28s;
        }

        .sentinel-data-stream-3 {
            top: 0;
            left: 0;
            width: 300px;
            height: 1.5px;
            background: linear-gradient(90deg, transparent 0%, rgba(56, 189, 248, 0.7) 50%, rgba(16, 185, 129, 0.4) 80%, transparent 100%);
            box-shadow: 0 0 12px rgba(56, 189, 248, 0.35);
            animation: streamDrift3 72s linear infinite;
            animation-delay: -44s;
        }

        /* Ambient Inward Drifting Particles (Cap: 16 Particles) */
        .sentinel-particle {
            position: absolute;
            border-radius: 50%;
            pointer-events: none !important;
            will-change: transform, opacity;
        }

        .sentinel-particle-1 { top: 5%; left: 6%; width: 3px; height: 3px; background: #00D2FF; box-shadow: 0 0 8px #00D2FF; animation: particleDrift1 34s linear infinite -4s; }
        .sentinel-particle-2 { top: 4%; left: 48%; width: 2.5px; height: 2.5px; background: #8B5CF6; box-shadow: 0 0 6px #8B5CF6; animation: particleDrift2 42s linear infinite -18s; }
        .sentinel-particle-3 { top: 6%; right: 8%; width: 3.5px; height: 3.5px; background: #06B6D4; box-shadow: 0 0 8px #06B6D4; animation: particleDrift3 38s linear infinite -11s; }
        .sentinel-particle-4 { top: 38%; right: 4%; width: 2.5px; height: 2.5px; background: #38BDF8; box-shadow: 0 0 6px #38BDF8; animation: particleDrift4 46s linear infinite -24s; }
        .sentinel-particle-5 { bottom: 6%; right: 7%; width: 3px; height: 3px; background: #6366F1; box-shadow: 0 0 8px #6366F1; animation: particleDrift5 36s linear infinite -8s; }
        .sentinel-particle-6 { bottom: 5%; left: 52%; width: 2.5px; height: 2.5px; background: #00D2FF; box-shadow: 0 0 6px #00D2FF; animation: particleDrift6 44s linear infinite -22s; }
        .sentinel-particle-7 { bottom: 8%; left: 6%; width: 3.5px; height: 3.5px; background: #8B5CF6; box-shadow: 0 0 8px #8B5CF6; animation: particleDrift7 39s linear infinite -15s; }
        .sentinel-particle-8 { top: 42%; left: 3%; width: 2.5px; height: 2.5px; background: #06B6D4; box-shadow: 0 0 6px #06B6D4; animation: particleDrift8 48s linear infinite -30s; }
        .sentinel-particle-9 { top: 16%; left: 18%; width: 3px; height: 3px; background: #38BDF8; box-shadow: 0 0 7px #38BDF8; animation: particleDrift9 32s linear infinite -6s; }
        .sentinel-particle-10 { top: 20%; right: 18%; width: 2.5px; height: 2.5px; background: #6366F1; box-shadow: 0 0 6px #6366F1; animation: particleDrift10 40s linear infinite -19s; }
        .sentinel-particle-11 { bottom: 22%; right: 17%; width: 3px; height: 3px; background: #00D2FF; box-shadow: 0 0 7px #00D2FF; animation: particleDrift11 35s linear infinite -13s; }
        .sentinel-particle-12 { bottom: 18%; left: 19%; width: 2.5px; height: 2.5px; background: #8B5CF6; box-shadow: 0 0 6px #8B5CF6; animation: particleDrift12 43s linear infinite -27s; }
        .sentinel-particle-13 { top: 3%; left: 66%; width: 3px; height: 3px; background: #06B6D4; box-shadow: 0 0 7px #06B6D4; animation: particleDrift13 37s linear infinite -9s; }
        .sentinel-particle-14 { bottom: 4%; left: 34%; width: 2.5px; height: 2.5px; background: #38BDF8; box-shadow: 0 0 6px #38BDF8; animation: particleDrift14 45s linear infinite -25s; }
        .sentinel-particle-15 { top: 62%; left: 5%; width: 3px; height: 3px; background: #6366F1; box-shadow: 0 0 7px #6366F1; animation: particleDrift15 33s linear infinite -5s; }
        .sentinel-particle-16 { top: 22%; right: 5%; width: 2.5px; height: 2.5px; background: #00D2FF; box-shadow: 0 0 6px #00D2FF; animation: particleDrift16 41s linear infinite -21s; }

        /* -------------------------------------------------------------------------- */
        /* 5. HERO SECTION & RADAR GRAPHIC                                            */
        /* -------------------------------------------------------------------------- */
        .hero-container {
            position: relative;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1.2rem 1.6rem;
            margin-bottom: 1.5rem;
            background: linear-gradient(135deg, rgba(19, 28, 46, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%);
            border: 1px solid var(--border-card);
            border-radius: 16px;
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            box-shadow: var(--shadow-glass);
            overflow: hidden;
            transition: transform 0.25s ease-out, border-color 0.25s ease-out, box-shadow 0.25s ease-out;
        }

        .hero-container:hover {
            transform: translateY(-2px);
            border-color: rgba(0, 210, 255, 0.3);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45), 0 0 16px rgba(0, 210, 255, 0.15);
        }

        .hero-text-area {
            position: relative;
            z-index: 2;
            max-width: 75%;
        }

        .hero-graphic-area {
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 120px;
            height: 120px;
            z-index: 1;
        }

        .radar-ring {
            position: absolute;
            border-radius: 50%;
            border: 1px solid rgba(0, 210, 255, 0.25);
            pointer-events: none;
        }
        .radar-ring-1 {
            width: 110px;
            height: 110px;
            border-style: dashed;
            animation: rotate 20s linear infinite;
        }
        .radar-ring-2 {
            width: 80px;
            height: 80px;
            border-color: rgba(139, 92, 246, 0.35);
            animation: pulse 4s ease-in-out infinite;
        }
        .radar-ring-3 {
            width: 50px;
            height: 50px;
            border-color: rgba(0, 210, 255, 0.5);
            background: radial-gradient(circle, rgba(0, 210, 255, 0.15) 0%, transparent 70%);
        }
        .radar-center-shield {
            font-size: 2.2rem;
            z-index: 3;
            animation: float 4s ease-in-out infinite;
        }

        .hero-desc {
            font-size: 0.95rem;
            color: var(--text-muted);
            margin-top: 0.3rem;
            margin-bottom: 0;
            line-height: 1.5;
        }

        /* -------------------------------------------------------------------------- */
        /* 6. STEP SEQUENCE & RADAR SPINNER                                           */
        /* -------------------------------------------------------------------------- */
        .step-sequence-box {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 14px;
            padding: 1.2rem 1.6rem;
            margin-bottom: 1.2rem;
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            box-shadow: var(--shadow-glass);
            transition: transform 0.25s ease-out, border-color 0.25s ease-out, box-shadow 0.25s ease-out;
        }

        .step-sequence-box:hover {
            transform: translateY(-2px);
            border-color: rgba(0, 210, 255, 0.3);
            box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4), 0 0 14px rgba(0, 210, 255, 0.15);
        }

        .step-row {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 0;
            color: var(--text-secondary);
            font-size: 0.95rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }
        .step-row:last-child {
            border-bottom: none;
        }
        .step-row.active {
            color: var(--accent-cyan);
            font-weight: 600;
        }
        .step-row.completed {
            color: var(--safe-green);
        }

        .step-spinner {
            border: 2px solid rgba(0, 210, 255, 0.2);
            border-top-color: var(--accent-cyan);
            border-radius: 50%;
            width: 16px;
            height: 16px;
            animation: rotate 0.8s linear infinite;
            display: inline-block;
        }

        /* -------------------------------------------------------------------------- */
        /* 7. GLASSMORPHIC RESULT CARDS                                               */
        /* -------------------------------------------------------------------------- */
        .result-glass-card-malware {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.16) 0%, rgba(15, 23, 42, 0.88) 100%);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(239, 68, 68, 0.5);
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.25), var(--shadow-glass);
            border-radius: 16px;
            padding: 1.8rem;
            text-align: center;
            margin: 1.2rem 0;
            animation: fadeInUp 0.4s ease;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease-out, box-shadow 0.2s ease-out;
        }

        .result-glass-card-malware:hover {
            transform: translateY(-5px);
            border-color: rgba(239, 68, 68, 0.7);
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.5), 0 0 32px rgba(239, 68, 68, 0.4);
        }

        .result-glass-card-benign {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.16) 0%, rgba(15, 23, 42, 0.88) 100%);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(16, 185, 129, 0.5);
            box-shadow: 0 0 25px rgba(16, 185, 129, 0.25), var(--shadow-glass);
            border-radius: 16px;
            padding: 1.8rem;
            text-align: center;
            margin: 1.2rem 0;
            animation: fadeInUp 0.4s ease;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease-out, box-shadow 0.2s ease-out;
        }

        .result-glass-card-benign:hover {
            transform: translateY(-5px);
            border-color: rgba(16, 185, 129, 0.7);
            box-shadow: 0 16px 40px rgba(0, 0, 0, 0.5), 0 0 32px rgba(16, 185, 129, 0.4);
        }

        /* -------------------------------------------------------------------------- */
        /* 8. GENERAL GLASSMORPHISM & CARD UTILITY CLASSES                            */
        /* -------------------------------------------------------------------------- */
        .glass-card, .cyber-card {
            background: var(--bg-card);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            border: 1px solid var(--border-card);
            border-radius: 14px;
            padding: 1.5rem;
            box-shadow: var(--shadow-glass);
            margin-bottom: 1.2rem;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease-out, box-shadow 0.2s ease-out;
        }

        .glass-card:hover, .cyber-card:hover {
            transform: translateY(-5px);
            border-color: var(--border-card-hover);
            box-shadow: 0 14px 40px rgba(0, 0, 0, 0.45), 0 0 20px rgba(0, 210, 255, 0.25);
        }

        .kpi-card {
            background: var(--bg-card);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-card);
            border-radius: 12px;
            padding: 1.2rem 1.0rem;
            text-align: center;
            box-shadow: var(--shadow-glass);
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease-out, box-shadow 0.2s ease-out;
        }

        .kpi-card:hover {
            border-color: var(--border-card-hover);
            transform: translateY(-4px);
            box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45), 0 0 18px rgba(0, 210, 255, 0.25);
        }

        .kpi-value {
            font-size: 1.9rem;
            font-weight: 800;
            color: var(--text-primary);
            letter-spacing: -0.5px;
        }

        .kpi-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 600;
            margin-top: 0.3rem;
        }

        /* -------------------------------------------------------------------------- */
        /* 9. GLOW UTILITY CLASSES                                                    */
        /* -------------------------------------------------------------------------- */
        .glow, .glow-cyan {
            border-color: var(--accent-cyan) !important;
            box-shadow: var(--shadow-glow-cyan) !important;
        }

        .glow-purple {
            border-color: var(--accent-purple) !important;
            box-shadow: var(--shadow-glow-purple) !important;
        }

        .glow-red {
            border-color: var(--warning-red) !important;
            box-shadow: var(--shadow-glow-red) !important;
        }

        .glow-green {
            border-color: var(--safe-green) !important;
            box-shadow: var(--shadow-glow-green) !important;
        }

        .glow-orange {
            border-color: var(--warning-orange) !important;
            box-shadow: 0 0 20px rgba(245, 158, 11, 0.35) !important;
        }

        /* -------------------------------------------------------------------------- */
        /* 10. UPLOAD CARD WITH HOVER GLOW & ELEVATION                                */
        /* -------------------------------------------------------------------------- */
        .glass-upload-card {
            background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-secondary) 100%);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 2px dashed rgba(0, 210, 255, 0.35);
            border-radius: 16px;
            padding: 2.2rem 1.5rem;
            text-align: center;
            box-shadow: var(--shadow-glass);
            margin-bottom: 1.2rem;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease-out, box-shadow 0.2s ease-out;
        }

        .glass-upload-card:hover {
            transform: translateY(-5px);
            border-color: var(--accent-cyan);
            box-shadow: 0 16px 44px rgba(0, 0, 0, 0.5), 0 0 24px rgba(0, 210, 255, 0.35);
        }

        .upload-icon {
            font-size: 2.8rem;
            margin-bottom: 0.5rem;
            display: inline-block;
        }

        .upload-heading {
            font-size: 1.35rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.4rem;
        }

        .upload-sub {
            font-size: 0.9rem;
            color: var(--text-muted);
            font-weight: 500;
        }

        .format-pills {
            display: inline-block;
            background: var(--accent-cyan-dim);
            color: var(--accent-cyan);
            border: 1px solid rgba(0, 210, 255, 0.25);
            border-radius: 20px;
            padding: 4px 16px;
            font-size: 0.82rem;
            font-weight: 600;
            letter-spacing: 0.5px;
            margin-top: 0.8rem;
        }

        .file-selected-card {
            background: linear-gradient(135deg, rgba(0, 210, 255, 0.08) 0%, rgba(139, 92, 246, 0.08) 100%);
            border: 1px solid rgba(0, 210, 255, 0.3);
            border-radius: 12px;
            padding: 1rem 1.4rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin: 0.8rem 0;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
            animation: fadeInUp 0.3s ease;
        }

        /* -------------------------------------------------------------------------- */
        /* 11. PRIMARY & DOWNLOAD BUTTON GRADIENTS & GLOW STYLING                    */
        /* -------------------------------------------------------------------------- */
        div.stButton > button[kind="primary"], div.stButton > button {
            background: linear-gradient(135deg, #00D2FF 0%, #3B82F6 50%, #8B5CF6 100%) !important;
            color: #080C16 !important;
            font-weight: 700 !important;
            font-size: 1.05rem !important;
            border-radius: 10px !important;
            border: none !important;
            padding: 0.65rem 1.5rem !important;
            box-shadow: 0 4px 20px rgba(0, 210, 255, 0.35) !important;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s ease-out, filter 0.2s ease-out !important;
            cursor: pointer !important;
        }

        div.stButton > button[kind="primary"]:hover, div.stButton > button:hover {
            transform: translateY(-2px) scale(1.02) !important;
            box-shadow: 0 8px 30px rgba(0, 210, 255, 0.6) !important;
            color: #000000 !important;
            filter: brightness(1.08) !important;
        }

        div.stButton > button[kind="primary"]:active, div.stButton > button:active {
            transform: scale(0.97) !important;
        }

        div.stButton > button:disabled {
            background: rgba(255, 255, 255, 0.05) !important;
            color: #64748B !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            box-shadow: none !important;
            transform: none !important;
            cursor: not-allowed !important;
        }

        div.stDownloadButton > button {
            background: linear-gradient(135deg, rgba(0, 210, 255, 0.12) 0%, rgba(139, 92, 246, 0.12) 100%) !important;
            color: #F8FAFC !important;
            border: 1px solid rgba(0, 210, 255, 0.35) !important;
            border-radius: 10px !important;
            font-weight: 600 !important;
            font-size: 0.92rem !important;
            padding: 0.55rem 1.2rem !important;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2) !important;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease-out, box-shadow 0.2s ease-out, color 0.2s ease-out, filter 0.2s ease-out !important;
        }

        div.stDownloadButton > button:hover {
            border-color: var(--accent-cyan) !important;
            box-shadow: 0 6px 24px rgba(0, 210, 255, 0.45) !important;
            transform: translateY(-2px) scale(1.02) !important;
            color: #00D2FF !important;
            filter: brightness(1.08) !important;
        }

        div.stDownloadButton > button:active {
            transform: scale(0.97) !important;
        }

        /* -------------------------------------------------------------------------- */
        /* 11b. METRICS, SIDEBAR, SECTIONS & CHART HOVER HIGHLIGHTS                   */
        /* -------------------------------------------------------------------------- */
        [data-testid="stMetric"] {
            background: var(--bg-card) !important;
            border: 1px solid var(--border-card) !important;
            border-radius: 12px !important;
            padding: 12px 14px !important;
            box-shadow: var(--shadow-glass) !important;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease-out, box-shadow 0.2s ease-out !important;
        }

        [data-testid="stMetric"]:hover {
            border-color: var(--border-card-hover) !important;
            transform: translateY(-4px) !important;
            box-shadow: 0 12px 30px rgba(0, 0, 0, 0.45), 0 0 18px rgba(0, 210, 255, 0.25) !important;
        }

        /* Sidebar Nav Items with Left-Border Accent Glow & Smooth Text Transition */
        [data-testid="stSidebar"] [data-testid="stRadio"] label {
            padding: 10px 14px !important;
            border-radius: 8px !important;
            border-left: 3px solid transparent !important;
            transition: background 0.2s ease, border-color 0.2s ease, transform 0.2s ease, color 0.2s ease !important;
            cursor: pointer !important;
            margin-bottom: 3px !important;
        }

        [data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
            background: rgba(0, 210, 255, 0.1) !important;
            border-left: 3px solid var(--accent-cyan) !important;
            box-shadow: inset 4px 0 12px -2px rgba(0, 210, 255, 0.35) !important;
            transform: translateX(4px) !important;
        }

        [data-testid="stSidebar"] [data-testid="stRadio"] label p,
        [data-testid="stSidebar"] [data-testid="stRadio"] label span,
        [data-testid="stSidebar"] [data-testid="stRadio"] label div {
            transition: color 0.2s ease, text-shadow 0.2s ease !important;
        }

        [data-testid="stSidebar"] [data-testid="stRadio"] label:hover p,
        [data-testid="stSidebar"] [data-testid="stRadio"] label:hover span {
            color: #FFFFFF !important;
            text-shadow: 0 0 8px rgba(0, 210, 255, 0.4) !important;
        }

        /* Plotly Chart Containers: Subtle Border Glow on Hover ONLY (Strictly No Movement/Scaling) */
        [data-testid="stPlotlyChart"] {
            border: 1px solid var(--border-card);
            border-radius: 12px;
            background: rgba(19, 28, 46, 0.4);
            padding: 4px;
            transition: border-color 0.22s ease-out, box-shadow 0.22s ease-out !important;
            transform: none !important;
            overflow: visible !important;
        }

        [data-testid="stPlotlyChart"]:hover {
            border-color: rgba(0, 210, 255, 0.4) !important;
            box-shadow: 0 0 20px rgba(0, 210, 255, 0.2), 0 6px 24px rgba(0, 0, 0, 0.3) !important;
            transform: none !important;
        }

        /* Ensure Plotly Hoverlayer / Tooltips Render On Top Without Distortion */
        .js-plotly-plot .plotly .hoverlayer {
            z-index: 9999 !important;
        }

        [data-testid="stFileUploader"] section {
            background: var(--bg-card) !important;
            border: 1px dashed rgba(0, 210, 255, 0.3) !important;
            border-radius: 12px !important;
            transition: border-color 0.25s ease, box-shadow 0.25s ease !important;
        }

        [data-testid="stFileUploader"] section:hover {
            border-color: var(--accent-cyan) !important;
            box-shadow: 0 0 15px rgba(0, 210, 255, 0.25) !important;
        }

        /* -------------------------------------------------------------------------- */
        /* 12. GENERAL HEADERS & FOOTER                                               */
        /* -------------------------------------------------------------------------- */
        .main-title {
            font-size: 2.2rem;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: var(--text-primary);
            margin-bottom: 0.2rem;
        }

        .sentinel-title {
            font-size: 2.5rem;
            font-weight: 900;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, var(--accent-cyan) 0%, #3B82F6 50%, var(--accent-purple) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.15rem;
            line-height: 1.15;
        }

        .sub-title {
            font-size: 1.05rem;
            color: var(--text-secondary);
            margin-bottom: 0.4rem;
            font-weight: 500;
        }

        .placeholder-box {
            background: var(--bg-secondary);
            border: 1px dashed var(--border-card);
            border-radius: 10px;
            padding: 1.5rem;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.9rem;
            margin: 0.8rem 0;
            transition: transform 0.25s ease-out, border-color 0.25s ease-out, box-shadow 0.25s ease-out;
        }

        .placeholder-box:hover {
            transform: translateY(-2px);
            border-color: rgba(0, 210, 255, 0.3);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35), 0 0 12px rgba(0, 210, 255, 0.15);
        }

        .workflow-box {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 10px;
            padding: 1.0rem 0.6rem;
            text-align: center;
            font-weight: 600;
            transition: transform 0.25s ease-out, border-color 0.25s ease-out, box-shadow 0.25s ease-out;
        }

        .workflow-box:hover {
            transform: translateY(-2px);
            border-color: rgba(0, 210, 255, 0.3);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35), 0 0 12px rgba(0, 210, 255, 0.15);
        }

        .section-container, .sentinel-section-box {
            background: var(--bg-card);
            border: 1px solid var(--border-card);
            border-radius: 14px;
            padding: 1.5rem;
            margin-bottom: 1.2rem;
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            box-shadow: var(--shadow-glass);
            transition: transform 0.25s ease-out, border-color 0.25s ease-out, box-shadow 0.25s ease-out;
        }

        .section-container:hover, .sentinel-section-box:hover {
            transform: translateY(-2px);
            border-color: rgba(0, 210, 255, 0.3);
            box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4), 0 0 14px rgba(0, 210, 255, 0.15);
        }

        .badge {
            display: inline-block;
            padding: 0.3em 0.7em;
            font-size: 80%;
            font-weight: 700;
            line-height: 1;
            text-align: center;
            border-radius: 6px;
        }

        .footer-text {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 3.5rem;
            padding-top: 1.2rem;
            border-top: 1px solid var(--border-card);
        }

        /* -------------------------------------------------------------------------- */
        /* 13. ANIMATED SECTION DIVIDERS                                              */
        /* -------------------------------------------------------------------------- */
        .sentinel-divider {
            display: flex;
            align-items: center;
            text-align: center;
            margin: 2.2rem 0;
            color: var(--accent-cyan);
            font-size: 0.95rem;
            letter-spacing: 3px;
        }
        .sentinel-divider::before, .sentinel-divider::after {
            content: '';
            flex: 1;
            border-bottom: 1px solid rgba(0, 210, 255, 0.25);
            box-shadow: 0 0 8px rgba(0, 210, 255, 0.4);
            animation: pulse 4s ease-in-out infinite;
        }
        .sentinel-divider:not(:empty)::before {
            margin-right: 1.2rem;
        }
        .sentinel-divider:not(:empty)::after {
            margin-left: 1.2rem;
        }

        /* -------------------------------------------------------------------------- */
        /* 14. FEATURE ANALYSIS CARDS WITH HOVER ELEVATION                            */
        /* -------------------------------------------------------------------------- */
        .feature-analysis-card {
            background: var(--bg-card);
            backdrop-filter: blur(14px);
            -webkit-backdrop-filter: blur(14px);
            border: 1px solid var(--border-card);
            border-radius: 14px;
            padding: 1.4rem;
            margin-bottom: 1.2rem;
            box-shadow: var(--shadow-glass);
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease-out, box-shadow 0.2s ease-out;
            height: 100%;
        }
        .feature-analysis-card:hover {
            transform: translateY(-5px);
            border-color: var(--border-card-hover);
            box-shadow: 0 14px 36px rgba(0, 0, 0, 0.45), 0 0 20px rgba(139, 92, 246, 0.3);
        }
        .feature-card-header {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 0.5rem;
        }
        .feature-card-desc {
            font-size: 0.85rem;
            color: var(--text-secondary);
            margin-bottom: 1rem;
            line-height: 1.4;
            min-height: 38px;
        }
        .feature-item-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 6px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            font-size: 0.88rem;
        }
        .feature-item-row:last-child {
            border-bottom: none;
        }
        .feature-item-name {
            color: var(--text-secondary);
        }
        /* -------------------------------------------------------------------------- */
        /* 15. CURSOR-TRACKING SPOTLIGHT HOVER EFFECT                                 */
        /* -------------------------------------------------------------------------- */
        .hover-spotlight {
            position: relative;
            overflow: hidden;
            --x: 50%;
            --y: 50%;
            --spotlight-opacity: 0;
            --spotlight-color: rgba(0, 210, 255, 0.16);
            --spotlight-size: 280px;
        }

        .hover-spotlight::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            pointer-events: none !important;
            border-radius: inherit;
            background: radial-gradient(
                circle var(--spotlight-size) at var(--x, 50%) var(--y, 50%),
                var(--spotlight-color, rgba(0, 210, 255, 0.16)) 0%,
                rgba(139, 92, 246, 0.04) 50%,
                transparent 80%
            );
            opacity: var(--spotlight-opacity, 0);
            transition: opacity 0.15s ease-out;
            z-index: 0;
        }

        .hover-spotlight:hover::before {
            opacity: 1;
        }

        .hover-spotlight > * {
            position: relative;
            z-index: 1;
        }

        .hover-spotlight.spotlight-malware {
            --spotlight-color: rgba(239, 68, 68, 0.22);
        }

        .hover-spotlight.spotlight-benign {
            --spotlight-color: rgba(16, 185, 129, 0.22);
        }

        .hover-spotlight.spotlight-purple {
            --spotlight-color: rgba(139, 92, 246, 0.18);
        }
        /* -------------------------------------------------------------------------- */
        /* 16. VIEWPORT ENTRANCE FADE-UP ANIMATIONS (STABLE CSS REVEAL)               */
        /* -------------------------------------------------------------------------- */
        .reveal-on-scroll {
            opacity: 1 !important;
            transform: translateY(0) !important;
            animation: fadeInUp 0.4s ease;
            will-change: opacity, transform;
        }

        .reveal-on-scroll.is-revealed {
            opacity: 1 !important;
            transform: translateY(0) !important;
        }

        @media (prefers-reduced-motion: reduce) {
            .reveal-on-scroll {
                opacity: 1 !important;
                transform: none !important;
                animation: none !important;
                transition: none !important;
            }
        }
        </style>

        <script>
        (function() {
            function attachSpotlight() {
                var d = (window.parent && window.parent.document) ? window.parent.document : document;
                if (!d || d._sentinelSpotlightBound) return;
                d._sentinelSpotlightBound = true;

                d.addEventListener('mousemove', function(e) {
                    var target = e.target;
                    while (target && target !== d) {
                        if (target.classList && target.classList.contains('hover-spotlight')) {
                            var rect = target.getBoundingClientRect();
                            var x = ((e.clientX - rect.left) / rect.width) * 100;
                            var y = ((e.clientY - rect.top) / rect.height) * 100;
                            target.style.setProperty('--x', x.toFixed(1) + '%');
                            target.style.setProperty('--y', y.toFixed(1) + '%');
                            target.style.setProperty('--spotlight-opacity', '1');
                            break;
                        }
                        target = target.parentElement;
                    }
                }, { passive: true });

                d.addEventListener('mouseout', function(e) {
                    var target = e.target;
                    while (target && target !== d) {
                        if (target.classList && target.classList.contains('hover-spotlight')) {
                            if (!e.relatedTarget || !target.contains(e.relatedTarget)) {
                                target.style.setProperty('--spotlight-opacity', '0');
                            }
                            break;
                        }
                        target = target.parentElement;
                    }
                }, { passive: true });
            }

            function initRevealObserver() {
                var d = (window.parent && window.parent.document) ? window.parent.document : document;
                if (!d) return;

                var elements = d.querySelectorAll('.reveal-on-scroll:not(.is-revealed)');
                if (!elements.length) return;

                if (!('IntersectionObserver' in window)) {
                    elements.forEach(function(el) { el.classList.add('is-revealed'); });
                    return;
                }

                var observer = new IntersectionObserver(function(entries, obs) {
                    entries.forEach(function(entry) {
                        if (entry.isIntersecting) {
                            entry.target.classList.add('is-revealed');
                            obs.unobserve(entry.target);
                        }
                    });
                }, {
                    root: null,
                    rootMargin: '0px 0px -20px 0px',
                    threshold: 0.05
                });

                elements.forEach(function(el) {
                    var rect = el.getBoundingClientRect();
                    if (rect.top < (window.innerHeight || document.documentElement.clientHeight) + 40 && rect.bottom > 0) {
                        el.classList.add('is-revealed');
                    } else {
                        observer.observe(el);
                    }
                });
            }

            if (document.readyState === 'complete' || document.readyState === 'interactive') {
                attachSpotlight();
                initRevealObserver();
            } else {
                document.addEventListener('DOMContentLoaded', function() {
                    attachSpotlight();
                    initRevealObserver();
                });
            }
            setTimeout(function() { attachSpotlight(); initRevealObserver(); }, 150);
            setTimeout(function() { attachSpotlight(); initRevealObserver(); }, 600);
            setTimeout(function() { initRevealObserver(); }, 1200);
        })();
        </script>

        <!-- Ambient Background Layer with Texture Grid, Drifting Orbs, Streams & Particles -->
        <div class="sentinel-ambient-bg" aria-hidden="true">
            <div class="sentinel-ambient-grid"></div>
            <div class="sentinel-orb sentinel-orb-1"></div>
            <div class="sentinel-orb sentinel-orb-2"></div>
            <div class="sentinel-orb sentinel-orb-3"></div>
            <div class="sentinel-orb sentinel-orb-4"></div>
            <div class="sentinel-orb sentinel-orb-5"></div>
            <div class="sentinel-orb sentinel-orb-6"></div>
            <div class="sentinel-data-stream sentinel-data-stream-1"></div>
            <div class="sentinel-data-stream sentinel-data-stream-2"></div>
            <div class="sentinel-data-stream sentinel-data-stream-3"></div>
            <div class="sentinel-particle sentinel-particle-1"></div>
            <div class="sentinel-particle sentinel-particle-2"></div>
            <div class="sentinel-particle sentinel-particle-3"></div>
            <div class="sentinel-particle sentinel-particle-4"></div>
            <div class="sentinel-particle sentinel-particle-5"></div>
            <div class="sentinel-particle sentinel-particle-6"></div>
            <div class="sentinel-particle sentinel-particle-7"></div>
            <div class="sentinel-particle sentinel-particle-8"></div>
            <div class="sentinel-particle sentinel-particle-9"></div>
            <div class="sentinel-particle sentinel-particle-10"></div>
            <div class="sentinel-particle sentinel-particle-11"></div>
            <div class="sentinel-particle sentinel-particle-12"></div>
            <div class="sentinel-particle sentinel-particle-13"></div>
            <div class="sentinel-particle sentinel-particle-14"></div>
            <div class="sentinel-particle sentinel-particle-15"></div>
            <div class="sentinel-particle sentinel-particle-16"></div>
        </div>
        """
        ),
        unsafe_allow_html=True,
    )


def render_animated_kpi_counters(cards: list, height: int = 115):
    """
    Renders animated KPI counters in a streamlit component.
    Smoothly counts up from 0 to target values on page load using native JavaScript animation.
    """
    import streamlit.components.v1 as components
    
    card_cols = len(cards) if cards else 4
    card_html_items = []
    
    for c in cards:
        val = c.get("value", 0)
        lbl = c.get("label", "")
        color = c.get("color", "#F8FAFC")
        suffix = c.get("suffix", "")
        is_float = "true" if c.get("is_float", False) else "false"
        
        card_html_items.append(
            f"""
            <div class="kpi-card">
                <div class="kpi-val" style="color: {color};" data-target="{val}" data-isfloat="{is_float}" data-suffix="{suffix}">0{suffix}</div>
                <div class="kpi-lbl">{lbl}</div>
            </div>
            """
        )
    
    cards_joined = "\n".join(card_html_items)
    
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap" rel="stylesheet">
    <style>
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        padding: 0;
        background: transparent;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        color: #F8FAFC;
        overflow: hidden;
      }}
      .kpi-grid {{
        display: grid;
        grid-template-columns: repeat({card_cols}, 1fr);
        gap: 14px;
        padding: 4px;
      }}
      .kpi-card {{
        position: relative;
        background: rgba(19, 28, 46, 0.72);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 14px 10px;
        text-align: center;
        box-shadow: 0 8px 24px 0 rgba(0, 0, 0, 0.35);
        transition: transform 0.25s ease, border-color 0.25s ease, box-shadow 0.25s ease;
        overflow: hidden;
      }}
      .kpi-card::before {{
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; bottom: 0;
        pointer-events: none;
        border-radius: inherit;
        background: radial-gradient(
          circle 180px at var(--x, 50%) var(--y, 50%),
          rgba(0, 210, 255, 0.16) 0%,
          rgba(139, 92, 246, 0.05) 50%,
          transparent 80%
        );
        opacity: var(--spotlight-opacity, 0);
        transition: opacity 0.22s ease;
        z-index: 1;
      }}
      .kpi-card:hover {{
        border-color: rgba(0, 210, 255, 0.4);
        transform: translateY(-2px);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.45);
      }}
      .kpi-card:hover::before {{
        opacity: 1;
      }}
      .kpi-val, .kpi-lbl {{
        position: relative;
        z-index: 2;
      }}
      .kpi-val {{
        font-size: 1.85rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        line-height: 1.15;
      }}
      .kpi-lbl {{
        font-size: 0.75rem;
        color: #94A3B8;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        font-weight: 600;
        margin-top: 6px;
      }}
    </style>
    </head>
    <body>
    <div class="kpi-grid">
      {cards_joined}
    </div>
    <script>
      function animateCounter(el, target, duration, isFloat, suffix) {{
        let startTime = null;
        function update(timestamp) {{
          if (!startTime) startTime = timestamp;
          const progress = Math.min((timestamp - startTime) / duration, 1);
          const ease = 1 - Math.pow(1 - progress, 3);
          const current = ease * target;
          if (isFloat) {{
            el.innerText = current.toFixed(1) + suffix;
          }} else {{
            el.innerText = Math.floor(current).toLocaleString() + suffix;
          }}
          if (progress < 1) {{
            requestAnimationFrame(update);
          }} else {{
            if (isFloat) {{
              el.innerText = target.toFixed(1) + suffix;
            }} else {{
              el.innerText = Math.round(target).toLocaleString() + suffix;
            }}
          }}
        }}
        requestAnimationFrame(update);
      }}

      window.addEventListener('DOMContentLoaded', () => {{
        document.querySelectorAll('.kpi-val').forEach(el => {{
          const target = parseFloat(el.getAttribute('data-target')) || 0;
          const isFloat = el.getAttribute('data-isfloat') === 'true';
          const suffix = el.getAttribute('data-suffix') || '';
          animateCounter(el, target, 1100, isFloat, suffix);
        }});

        document.querySelectorAll('.kpi-card').forEach(card => {{
          card.addEventListener('mousemove', (e) => {{
            const rect = card.getBoundingClientRect();
            const x = ((e.clientX - rect.left) / rect.width) * 100;
            const y = ((e.clientY - rect.top) / rect.height) * 100;
            card.style.setProperty('--x', x.toFixed(1) + '%');
            card.style.setProperty('--y', y.toFixed(1) + '%');
            card.style.setProperty('--spotlight-opacity', '1');
          }}, {{ passive: true }});
          card.addEventListener('mouseleave', () => {{
            card.style.setProperty('--spotlight-opacity', '0');
          }}, {{ passive: true }});
        }});
      }});
    </script>
    </body>
    </html>
    """
    components.html(full_html, height=height)
