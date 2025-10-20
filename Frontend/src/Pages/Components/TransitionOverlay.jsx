import { useEffect, useState } from "react";
import "../Styles/TransitionOverlay.css"; 
import { useLocation } from "react-router-dom";

export default function TransitionOverlay() {
  const location = useLocation();
  const [active, setActive] = useState(false);

  useEffect(() => {
    // Trigger overlay on route change
    setActive(true);

    const timer = setTimeout(() => {
      setActive(false);
    }, 2500); // Total animation duration

    return () => clearTimeout(timer);
  }, [location]);

  // Get route name for display
  const getRouteName = (pathname) => {
    const name = pathname.replace("/", "").split("/")[0];
    return name.charAt(0).toUpperCase() + name.slice(1) || "Home";
  };

  return (
    <div className={`transition-overlay ${active ? "active" : ""}`}>
      <h1 className="overlay-title">
        {getRouteName(location.pathname)}
      </h1>
    </div>
  );
}