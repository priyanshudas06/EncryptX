document.addEventListener('DOMContentLoaded', () => {
    const sendOtpBtn = document.getElementById('sendOtpBtn');
    const verifyOtpBtn = document.getElementById('verifyOtpBtn');
    const signupBtn = document.getElementById('signupBtn');
    const otpGroup = document.querySelectorAll('.otp-group');
    const signupForm = document.getElementById('signupForm');

    // Send OTP
    sendOtpBtn.addEventListener('click', async () => {
        const email = document.getElementById('email').value;

        if (!email) {
            alert('Please enter your email address.');
            return;
        }
        
        //check the email already exists or not
        const checkResponse = await fetch('/check-mail', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
        });
        const checkData = await checkResponse.json();
    
        if (checkData.temp) {
            alert('The email is already used.');
            return;
        }


        // Call backend API to send OTP
        const response = await fetch('/send-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email }),
        });

        if (response.ok) {
            alert('OTP sent to your email.');
            otpGroup.forEach(group => group.style.display = 'block');
        } else {
            alert('Failed to send OTP. Try again.');
        }
    });

    // Verify OTP
    verifyOtpBtn.addEventListener('click', async () => {
        const email = document.getElementById('email').value;
        const otp = document.getElementById('otp').value;

        if (!otp) {
            alert('Please enter the OTP.');
            return;
        }

        // Call backend API to verify OTP
        const response = await fetch('/verify-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, otp }),
        });

        if (response.ok) {
            alert('OTP verified successfully.');
            signupBtn.disabled = false;  // Enable the signup button after OTP is verified
        } else {
            alert('Invalid or expired OTP. Try again.');
        }
    });

    // Handle form submission
    signupForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;

        if (!username || !email || !password) {
            alert('Please fill all fields.');
            return;
        }

        const data = {
            username,
            email,
            password
        };

        // Send the form data to Flask backend
        const response = await fetch('/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });

        if (response.ok) {
            alert('Sign-up successful!');
            window.location.href = '/login';
        } else {
            alert('Failed to register. Please try again.');
        }
    });
});
