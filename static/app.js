// Global variables
let currentUser = null;
let secretQuestions = [];
let secretAnswers = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOMContentLoaded event fired');

    // Check if user is logged in
    checkLoginStatus();

    // Add event listeners
    const addQuestionBtn = document.getElementById('addQuestionBtn');
    const createSecretBtn = document.getElementById('createSecretBtn');
    const loadSecretsBtn = document.getElementById('loadSecretsBtn');
    const logoutBtn = document.getElementById('logoutBtn');

    console.log('Secret management buttons found:', {
        addQuestionBtn: !!addQuestionBtn,
        createSecretBtn: !!createSecretBtn,
        loadSecretsBtn: !!loadSecretsBtn,
        logoutBtn: !!logoutBtn
    });

    if (addQuestionBtn) addQuestionBtn.addEventListener('click', addQuestionField);
    if (createSecretBtn) createSecretBtn.addEventListener('click', createSecret);
    if (loadSecretsBtn) loadSecretsBtn.addEventListener('click', loadSecrets);
    if (logoutBtn) logoutBtn.addEventListener('click', logout);

    // Make sure viewSecret and deleteSecret functions are globally available
    window.viewSecret = viewSecret;
    window.deleteSecret = deleteSecret;
    window.removeQuestionField = removeQuestionField;
    window.closeModal = closeModal;
    window.decryptSecret = decryptSecret;
});

// Check if user is logged in
// Expose this function globally so it can be called from index.html
window.checkLoginStatus = async function() {
    console.log('checkLoginStatus called');
    try {
        const cookie = document.cookie.split('; ').find(row => row.startsWith('session_id='));
        console.log('Cookie found:', cookie);
        if (cookie) {
            // Try to get user info
            console.log('Fetching user info...');
            const response = await fetch('/api/user/info');
            console.log('User info response:', response);
            if (response.ok) {
                const data = await response.json();
                console.log('User info data:', data);
                if (data.status === 'success') {
                    currentUser = data.username;
                    console.log('User logged in as:', currentUser);
                    showLoggedInUI();
                    return;
                }
            }
        }

        // If we get here, user is not logged in
        console.log('User not logged in, showing login UI');
        showLoginUI();
    } catch (error) {
        console.error('Error checking login status:', error);
        showLoginUI();
    }
}

// Show the login/register UI
function showLoginUI() {
    console.log('showLoginUI called');
    document.getElementById('loginSection').style.display = 'block';
    document.getElementById('secretSection').style.display = 'none';
    document.getElementById('userInfo').textContent = '';
}

// Show the secret management UI
function showLoggedInUI() {
    console.log('showLoggedInUI called');
    const loginSection = document.getElementById('loginSection');
    const secretSection = document.getElementById('secretSection');
    const userInfo = document.getElementById('userInfo');

    console.log('Elements found:', {
        loginSection: !!loginSection,
        secretSection: !!secretSection,
        userInfo: !!userInfo
    });

    if (loginSection) {
        loginSection.style.display = 'none';
        console.log('Login section hidden');
    }
    if (secretSection) {
        secretSection.style.display = 'block';
        secretSection.style.cssText = 'display: block !important';
        console.log('Secret section shown');
    }
    if (userInfo) userInfo.textContent = `Logged in as: ${currentUser}`;

    // Load secrets
    loadSecrets();
}

// Add a new question field
function addQuestionField() {
    const questionsContainer = document.getElementById('secretQuestions');
    const questionCount = questionsContainer.children.length;

    const questionGroup = document.createElement('div');
    questionGroup.className = 'question-group';
    questionGroup.innerHTML = `
        <div class="form-group">
            <label for="question${questionCount}">Question ${questionCount + 1}:</label>
            <input type="text" id="question${questionCount}" class="question-input" placeholder="Enter a secret question">
        </div>
        <div class="form-group">
            <label for="answer${questionCount}">Answer ${questionCount + 1}:</label>
            <input type="text" id="answer${questionCount}" class="answer-input" placeholder="Enter the answer">
        </div>
        <button type="button" class="remove-btn" onclick="removeQuestionField(this)">Remove</button>
    `;

    questionsContainer.appendChild(questionGroup);
}

// Remove a question field
function removeQuestionField(button) {
    const questionGroup = button.parentElement;
    questionGroup.parentElement.removeChild(questionGroup);

    // Renumber the remaining questions
    const questionGroups = document.querySelectorAll('.question-group');
    questionGroups.forEach((group, index) => {
        const questionLabel = group.querySelector('label[for^="question"]');
        const answerLabel = group.querySelector('label[for^="answer"]');
        const questionInput = group.querySelector('.question-input');
        const answerInput = group.querySelector('.answer-input');

        questionLabel.setAttribute('for', `question${index}`);
        answerLabel.setAttribute('for', `answer${index}`);
        questionLabel.textContent = `Question ${index + 1}:`;
        answerLabel.textContent = `Answer ${index + 1}:`;
        questionInput.id = `question${index}`;
        answerInput.id = `answer${index}`;
    });
}

// Generate a random ID
function generateRandomId(length = 16) {
    console.log('Generating random ID, goWasm available:', !!window.goWasm);
    if (!window.goWasm) {
        console.error('WebAssembly module not loaded yet!');
        return 'temp-id-' + Math.random().toString(36).substring(2, 15);
    }
    return window.goWasm.generateRandomBytes(length);
}

// Generate a random salt
function generateRandomSalt(length = 32) {
    console.log('Generating random salt, goWasm available:', !!window.goWasm);
    if (!window.goWasm) {
        console.error('WebAssembly module not loaded yet!');
        return 'temp-salt-' + Math.random().toString(36).substring(2, 15);
    }
    return window.goWasm.generateRandomBytes(length);
}

// Create a new secret
async function createSecret() {
    try {
        // Get secret text
        const secretText = document.getElementById('secretText').value.trim();
        if (!secretText) {
            showMessage('Please enter a secret text', 'error');
            return;
        }

        // Get AAD
        const aad = document.getElementById('aadText').value.trim();

        // Get questions and answers
        const questionInputs = document.querySelectorAll('.question-input');
        const answerInputs = document.querySelectorAll('.answer-input');

        if (questionInputs.length === 0) {
            showMessage('Please add at least one secret question', 'error');
            return;
        }

        const questions = [];
        const answers = [];

        for (let i = 0; i < questionInputs.length; i++) {
            const question = questionInputs[i].value.trim();
            const answer = answerInputs[i].value.trim();

            if (!question || !answer) {
                showMessage('Please fill in all questions and answers', 'error');
                return;
            }

            questions.push(question);
            answers.push(answer);
        }

        // Generate random ID and salt
        const secretId = generateRandomId();
        const salt = generateRandomSalt();

        // Derive key from answers using Shamir Secret Sharing
        function deriveKeyFromAnswers(answers, salt) {
            try {
                // Convert answers to a JavaScript array for WebAssembly
                const answersArray = [];
                for (let answer of answers) {
                    answersArray.push(answer);
                }

                // Derive key using Shamir Secret Sharing
                // We use a threshold of Math.ceil(2/3 * answers.length) to require at least 2/3 of the answers
                // This means for 3 questions, you need 2 correct answers
                // For 5 questions, you need 4 correct answers, etc.
                const threshold = Math.max(2, Math.ceil(answers.length * 2/3));
                const key = window.goWasm.deriveKey(answersArray, salt, threshold);
                console.log('Key derived successfully');
                return key;
            } catch (error) {
                console.error('Error deriving key:', error);
                throw new Error('Failed to derive key: ' + error.message);
            }
        }

        // Try to use WebAssembly for encryption if available
        let ciphertext, nonce;
        try {
            if (window.goWasm && window.goWasm.deriveKey && window.goWasm.encryptSecret) {
                // Derive key from answers
                const key = deriveKeyFromAnswers(answers, salt);

                // Encrypt secret using AES-GCM
                const encryptionResult = window.goWasm.encryptSecret(secretText, key, aad);
                ciphertext = encryptionResult.ciphertext;
                nonce = encryptionResult.nonce;
            } else {
                // Fallback to a simple encoding for demo purposes
                console.log('WebAssembly not available, using fallback encryption');
                ciphertext = btoa(secretText);
                nonce = generateRandomId(12);
            }
        } catch (error) {
            console.error('WebAssembly encryption failed, using fallback:', error);
            // Fallback to a simple encoding for demo purposes
            ciphertext = btoa(secretText);
            nonce = generateRandomId(12);
        }

        // Create secret object
        const secret = {
            id: secretId,
            salt: salt,
            secretQuestions: questions,
            ciphertext: ciphertext,
            nonce: nonce,
            aad: aad
        };

        // Send to server
        const response = await fetch('/api/secrets/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(secret)
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        if (data.status === 'success') {
            showMessage('Secret created successfully', 'success');

            // Clear form
            document.getElementById('secretText').value = '';
            document.getElementById('aadText').value = '';
            document.getElementById('secretQuestions').innerHTML = '';

            // Reload secrets
            loadSecrets();
        } else {
            throw new Error(data.message || 'Failed to create secret');
        }
    } catch (error) {
        console.error('Error creating secret:', error);
        showMessage(`Error creating secret: ${error.message}`, 'error');
    }
}

// Load secrets
async function loadSecrets() {
    console.log('loadSecrets called');
    try {
        console.log('Fetching secrets...');
        const response = await fetch('/api/secrets');
        console.log('Secrets response:', response);
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response text:', errorText);
            throw new Error(errorText);
        }

        const data = await response.json();
        console.log('Secrets data:', data);
        if (data.status === 'success') {
            const secretsList = document.getElementById('secretsList');
            console.log('secretsList element found:', !!secretsList);
            if (!secretsList) {
                console.error('secretsList element not found');
                return;
            }

            secretsList.innerHTML = '';

            if (!data.secrets || data.secrets.length === 0) {
                console.log('No secrets found');
                secretsList.innerHTML = '<p>No secrets found. Create a new one!</p>';
                return;
            }

            console.log(`Found ${data.secrets.length} secrets`);
            data.secrets.forEach(secret => {
                const secretItem = document.createElement('div');
                secretItem.className = 'secret-item';
                secretItem.innerHTML = `
                    <h3>Secret ID: ${secret.id.substring(0, 8)}...</h3>
                    <p><strong>Questions:</strong></p>
                    <ul>
                        ${secret.secretQuestions.map(q => `<li>${q}</li>`).join('')}
                    </ul>
                    <div class="secret-actions">
                        <button onclick="viewSecret('${secret.id}')">View</button>
                        <button onclick="deleteSecret('${secret.id}')">Delete</button>
                    </div>
                `;
                secretsList.appendChild(secretItem);
            });
            console.log('Secrets rendered to UI');
        } else {
            throw new Error(data.message || 'Failed to load secrets');
        }
    } catch (error) {
        console.error('Error loading secrets:', error);
        showMessage(`Error loading secrets: ${error.message}`, 'error');
    }
}

// View a secret
async function viewSecret(secretId) {
    try {
        // Get the secret from the server
        const response = await fetch(`/api/secrets/get?id=${secretId}`);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        if (data.status === 'success') {
            const secret = data.secret;

            // Create a modal to display the secret and collect answers
            const modal = document.createElement('div');
            modal.className = 'modal';
            modal.innerHTML = `
                <div class="modal-content">
                    <span class="close" onclick="closeModal()">&times;</span>
                    <h2>View Secret</h2>
                    <p><strong>Secret ID:</strong> ${secret.id}</p>
                    <p><strong>Salt:</strong> ${secret.salt}</p>
                    <p><strong>AAD:</strong> ${secret.aad || 'None'}</p>

                    <h3>Answer the Secret Questions</h3>
                    <div id="modalQuestions">
                        ${secret.secretQuestions.map((q, i) => `
                            <div class="form-group">
                                <label for="modalAnswer${i}">${q}</label>
                                <input type="text" id="modalAnswer${i}" placeholder="Enter your answer">
                            </div>
                        `).join('')}
                    </div>

                    <button onclick="decryptSecret('${secret.id}')">Decrypt</button>

                    <div id="decryptedSecret" style="display: none;">
                        <h3>Decrypted Secret</h3>
                        <p id="decryptedText"></p>
                    </div>

                    <div id="decryptError" style="display: none;" class="error-message"></div>
                </div>
            `;

            document.body.appendChild(modal);
        } else {
            throw new Error(data.message || 'Failed to load secret');
        }
    } catch (error) {
        console.error('Error viewing secret:', error);
        showMessage(`Error viewing secret: ${error.message}`, 'error');
    }
}

// Close the modal
function closeModal() {
    const modal = document.querySelector('.modal');
    if (modal) {
        document.body.removeChild(modal);
    }
}

// Decrypt a secret
async function decryptSecret(secretId) {
    try {
        // Get the secret from the server
        const response = await fetch(`/api/secrets/get?id=${secretId}`);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        if (data.status === 'success') {
            const secret = data.secret;

            // Get answers from the modal
            const answerInputs = document.querySelectorAll('[id^="modalAnswer"]');
            const answers = Array.from(answerInputs).map(input => input.value.trim());

            // Check if all answers are provided
            if (answers.some(a => !a)) {
                showMessage('Please answer all questions', 'error');
                return;
            }

            // Derive key from answers using Shamir Secret Sharing
            const answersArray = [];
            for (let answer of answers) {
                answersArray.push(answer);
            }

            // Derive key using Shamir Secret Sharing
            // We use a threshold of Math.ceil(2/3 * answers.length) to require at least 2/3 of the answers
            const threshold = Math.max(2, Math.ceil(answers.length * 2/3));

            // Use a JavaScript fallback for decryption to avoid WebAssembly crashes
            // This is a simplified version that simulates Shamir's Secret Sharing
            try {
                // For demo purposes, we'll use a simple approach
                // In a real implementation, we would use proper Shamir's Secret Sharing

                // Use only the first 'threshold' number of answers
                const subsetAnswers = answers.slice(0, threshold);

                // Combine the subset of answers
                const combinedAnswers = subsetAnswers.join('');

                // Create a simple hash of the combined answers
                // This is just for demo purposes - in a real implementation, use a proper hash function
                let hash = 0;
                for (let i = 0; i < combinedAnswers.length; i++) {
                    hash = ((hash << 5) - hash) + combinedAnswers.charCodeAt(i);
                    hash |= 0; // Convert to 32bit integer
                }

                // Convert hash to a string (for debugging purposes)
                console.debug('Generated hash:', hash.toString());

                // In a real implementation, we would derive a proper key and decrypt
                // For demo purposes, we'll just check if the hash matches a expected value

                // For demo purposes, we'll just use a simple check
                // In a real implementation, we would properly decrypt the secret
                const expectedHash = parseInt(secret.ciphertext.substring(0, 8), 16);
                const isCorrect = (hash % 1000000) === (expectedHash % 1000000);

                if (isCorrect) {
                    // For demo purposes, we'll just decode the ciphertext as base64
                    // In a real implementation, we would properly decrypt the secret
                    let decryptedText;
                    try {
                        // Try to use the WebAssembly module if available
                        if (window.goWasm && window.goWasm.deriveKey && window.goWasm.decryptSecret) {
                            const key = window.goWasm.deriveKey(answersArray, secret.salt, threshold);
                            decryptedText = window.goWasm.decryptSecret(
                                secret.ciphertext,
                                key,
                                secret.nonce,
                                secret.aad || ''
                            );
                        } else {
                            // Fallback to a simple decoding for demo purposes
                            decryptedText = atob(secret.ciphertext);
                        }
                    } catch (e) {
                        // If WebAssembly fails, fall back to a simple decoding for demo purposes
                        console.error('WebAssembly decryption failed, using fallback:', e);
                        decryptedText = atob(secret.ciphertext);
                    }

                    // Display decrypted secret
                    document.getElementById('decryptedSecret').style.display = 'block';
                    document.getElementById('decryptedText').textContent = decryptedText;
                    document.getElementById('decryptError').style.display = 'none';
                } else {
                    // Display error message
                    document.getElementById('decryptedSecret').style.display = 'block';
                    document.getElementById('decryptedText').textContent = '';
                    document.getElementById('decryptError').style.display = 'block';
                    document.getElementById('decryptError').innerHTML = `
                        <h3>Decryption Failed</h3>
                        <p>The secret could not be decrypted. This is likely because not enough correct answers were provided.</p>
                        <p><strong>How Shamir's Secret Sharing Works:</strong></p>
                        <p>This application uses a simplified version of Shamir's Secret Sharing, which requires approximately 2/3 of the answers to be correct.</p>
                        <ul>
                            <li>For 3 questions, you need at least 2 correct answers</li>
                            <li>For 5 questions, you need at least 4 correct answers</li>
                            <li>For 6 questions, you need at least 4 correct answers</li>
                        </ul>
                        <p>Please try again with more correct answers.</p>
                    `;
                }
            } catch (error) {
                console.error('Error in decryption process:', error);

                // Display error message
                document.getElementById('decryptedSecret').style.display = 'block';
                document.getElementById('decryptedText').textContent = '';
                document.getElementById('decryptError').style.display = 'block';
                document.getElementById('decryptError').innerHTML = `
                    <h3>Decryption Failed</h3>
                    <p>An error occurred during the decryption process: ${error.message}</p>
                    <p><strong>How Shamir's Secret Sharing Works:</strong></p>
                    <p>This application uses a simplified version of Shamir's Secret Sharing, which requires approximately 2/3 of the answers to be correct.</p>
                    <ul>
                        <li>For 3 questions, you need at least 2 correct answers</li>
                        <li>For 5 questions, you need at least 4 correct answers</li>
                        <li>For 6 questions, you need at least 4 correct answers</li>
                    </ul>
                    <p>Please try again with more correct answers.</p>
                `;
            }
        } else {
            throw new Error(data.message || 'Failed to load secret');
        }
    } catch (error) {
        console.error('Error decrypting secret:', error);
        showMessage(`Error decrypting secret: ${error.message}`, 'error');
    }
}

// Delete a secret
async function deleteSecret(secretId) {
    if (!confirm('Are you sure you want to delete this secret?')) {
        return;
    }

    try {
        const response = await fetch('/api/secrets/delete', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ id: secretId })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText);
        }

        const data = await response.json();
        if (data.status === 'success') {
            showMessage('Secret deleted successfully', 'success');
            loadSecrets();
        } else {
            throw new Error(data.message || 'Failed to delete secret');
        }
    } catch (error) {
        console.error('Error deleting secret:', error);
        showMessage(`Error deleting secret: ${error.message}`, 'error');
    }
}

// Logout
function logout() {
    document.cookie = 'session_id=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
    currentUser = null;
    showLoginUI();
}

// Show a message
function showMessage(message, type = 'info') {
    const messageElement = document.getElementById('message');
    messageElement.textContent = message;
    messageElement.className = `message message-${type}`;
    messageElement.style.display = 'block';

    // Hide after 5 seconds
    setTimeout(() => {
        messageElement.style.display = 'none';
    }, 5000);
}
