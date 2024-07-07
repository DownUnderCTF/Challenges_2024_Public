document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('feedbackForm');
    
    if (form) {
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            submitFeedback();
        });
    }

    function submitFeedback() {
        const feedback = {
            title: document.getElementById('title').value,
            content: document.getElementById('content').value,
            rating: document.getElementById('rating').value,
            referred: document.getElementById('referred').value
        };

        fetch('/save_feedback', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(feedback)
        })
        .then(response => response.text())
        .then(data => {
            alert(data);
            form.reset();
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
});
