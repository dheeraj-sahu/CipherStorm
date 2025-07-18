// device.js
(function setupDeviceId() {
    // Check if we already have a device ID saved
    let deviceId = localStorage.getItem("device_id");
    
    // If we don't have one, create a new one
    if (!deviceId) {
        deviceId = crypto.randomUUID();
        localStorage.setItem("device_id", deviceId);
        console.log("New Device ID created:", deviceId);
    } else {
        console.log("Using existing Device ID:", deviceId);
    }
    
    // Save device ID as a cookie so backend can read it
    document.cookie = `device_id=${deviceId}; path=/; max-age=31536000`;
    
    // Get user location info using their IP address
    function getUserLocationInfo() {
        fetch('https://ipapi.co/json/')
            .then(response => response.json())
            .then(data => {
                console.log("User Location Info:", {
                    country: data.country_name || "Unknown",
                    city: data.city || "Unknown",
                    latitude: data.latitude || null,
                    longitude: data.longitude || null,
                    ip: data.ip || "Unknown"
                });
                
                // Save location info for later use
                window.USER_LOCATION = {
                    country: data.country_name || "Unknown",
                    city: data.city || "Unknown",
                    latitude: data.latitude || null,
                    longitude: data.longitude || null,
                    ip: data.ip || "Unknown"
                };
            })
            .catch(error => {
                console.log("Could not get location info:", error);
                window.USER_LOCATION = {
                    country: "Unknown",
                    city: "Unknown",
                    latitude: null,
                    longitude: null,
                    ip: "Unknown"
                };
            });
    }
    
    // Get location info when page loads
    getUserLocationInfo();
    
    // Add device ID to all fetch requests automatically
    const originalFetch = window.fetch;
    window.fetch = function(url, options = {}) {
        // Make sure headers exist
        if (!options.headers) {
            options.headers = {};
        }
        
        // Add device ID header
        options.headers['X-Device-ID'] = deviceId;
        
        // Call the original fetch
        return originalFetch(url, options);
    };
})();