// Basic interactivity
document.addEventListener('DOMContentLoaded', function() {
    
    // Auto-hide flash messages
    const flashMessages = document.querySelectorAll('.flash-messages li');
    if (flashMessages.length > 0) {
        setTimeout(() => {
            flashMessages.forEach(msg => {
                msg.style.opacity = '0';
                setTimeout(() => msg.remove(), 500);
            });
        }, 3000);
    }

    // Toggle password visibility (if icon exists)
    // Add eye icon logic if you add icons to the HTML
});
