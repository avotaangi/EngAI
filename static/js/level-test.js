document.addEventListener('DOMContentLoaded', function() {
    const startBtn = document.getElementById('startTestBtn');
    const testStart = document.getElementById('testStart');
    const testLoading = document.getElementById('testLoading');
    const testQuestions = document.getElementById('testQuestions');
    const testResults = document.getElementById('testResults');
    
    let currentTest = {
        id: null,
        questions: [],
        answers: [],
        currentQuestion: 0
    };
    
    // Начало теста
    if (startBtn) {
        startBtn.addEventListener('click', function() {
            startTest();
        });
    }
    
    // Начало теста
    async function startTest() {
        testStart.style.display = 'none';
        testLoading.style.display = 'block';
        testQuestions.style.display = 'none';
        testResults.style.display = 'none';
        
        try {
            const response = await fetch('/api/level-test/start/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                }
            });
            
            const data = await response.json();
            
            if (data.error) {
                alert('Ошибка: ' + data.error);
                testStart.style.display = 'block';
                testLoading.style.display = 'none';
                return;
            }
            
            currentTest.id = data.test_id;
            currentTest.questions = data.questions;
            currentTest.answers = new Array(data.questions.length).fill(-1);
            currentTest.currentQuestion = 0;
            
            testLoading.style.display = 'none';
            testQuestions.style.display = 'block';
            
            renderQuestion(0);
            
        } catch (error) {
            console.error('Error starting test:', error);
            alert('Произошла ошибка при загрузке теста');
            testStart.style.display = 'block';
            testLoading.style.display = 'none';
        }
    }
    
    // Отображение вопроса
    function renderQuestion(index) {
        const question = currentTest.questions[index];
        const container = document.getElementById('questionContainer');
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        const prevBtn = document.getElementById('prevQuestionBtn');
        const nextBtn = document.getElementById('nextQuestionBtn');
        const submitBtn = document.getElementById('submitTestBtn');
        
        // Обновляем прогресс
        const progress = ((index + 1) / currentTest.questions.length) * 100;
        progressFill.style.width = progress + '%';
        const questionType = question.type === 'grammar' ? 'Грамматика' : question.type === 'vocabulary' ? 'Лексика' : 'Письмо';
        progressText.textContent = `Вопрос ${index + 1} из ${currentTest.questions.length} (${questionType})`;
        
        // Отображаем вопрос
        const questionTypeLabel = question.type === 'grammar' ? 'Грамматика' : question.type === 'vocabulary' ? 'Лексика' : 'Письмо';
        container.innerHTML = `
            <div class="question-item active">
                <div class="question-type-badge question-type-${question.type}">${questionTypeLabel}</div>
                <div class="question-text">${escapeHtml(question.question)}</div>
                <div class="question-options">
                    ${question.options.map((option, optIndex) => `
                        <div class="option-item ${currentTest.answers[index] === optIndex ? 'selected' : ''}" 
                             data-option="${optIndex}">
                            ${escapeHtml(option)}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        
        // Обработчики выбора ответа
        container.querySelectorAll('.option-item').forEach(item => {
            item.addEventListener('click', function() {
                container.querySelectorAll('.option-item').forEach(opt => opt.classList.remove('selected'));
                this.classList.add('selected');
                currentTest.answers[index] = parseInt(this.dataset.option);
            });
        });
        
        // Кнопки навигации
        prevBtn.style.display = index > 0 ? 'block' : 'none';
        nextBtn.style.display = index < currentTest.questions.length - 1 ? 'block' : 'none';
        submitBtn.style.display = index === currentTest.questions.length - 1 ? 'block' : 'none';
        
        // Обработчики кнопок
        prevBtn.onclick = () => {
            if (index > 0) {
                currentTest.currentQuestion = index - 1;
                renderQuestion(currentTest.currentQuestion);
            }
        };
        
        nextBtn.onclick = () => {
            if (index < currentTest.questions.length - 1) {
                currentTest.currentQuestion = index + 1;
                renderQuestion(currentTest.currentQuestion);
            }
        };
        
        submitBtn.onclick = submitTest;
    }
    
    // Отправка теста
    async function submitTest() {
        // Проверяем, что все вопросы отвечены
        const unanswered = currentTest.answers.filter(a => a === -1).length;
        if (unanswered > 0) {
            if (!confirm(`Вы не ответили на ${unanswered} вопросов. Завершить тест?`)) {
                return;
            }
        }
        
        testQuestions.style.display = 'none';
        testLoading.style.display = 'block';
        
        try {
            const response = await fetch('/api/level-test/submit/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken')
                },
                body: JSON.stringify({
                    test_id: currentTest.id,
                    answers: currentTest.answers
                })
            });
            
            const data = await response.json();
            
            if (data.error) {
                alert('Ошибка: ' + data.error);
                testLoading.style.display = 'none';
                testQuestions.style.display = 'block';
                return;
            }
            
            // Отображаем результаты
            testLoading.style.display = 'none';
            testResults.style.display = 'block';
            
            // Прокручиваем к результатам
            testResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
            
            document.getElementById('resultLevelValue').textContent = data.detected_level || 'Не определен';
            document.getElementById('resultScoreValue').textContent = `${data.score}/${data.max_score}`;
            
            const analysisDiv = document.getElementById('resultAnalysis');
            if (data.analysis) {
                analysisDiv.innerHTML = `<p>${escapeHtml(data.analysis)}</p>`;
            } else {
                analysisDiv.innerHTML = '<p>Анализ результатов будет доступен после завершения теста.</p>';
            }
            
            // Отображаем рекомендуемые темы
            const topicsList = document.getElementById('topicsList');
            if (data.recommended_topics && data.recommended_topics.length > 0) {
                topicsList.innerHTML = data.recommended_topics.map(topic => `
                    <div class="topic-item">
                        <div class="topic-name">${escapeHtml(topic.name)}</div>
                        <div class="topic-description">${escapeHtml(topic.description || '')}</div>
                        ${topic.priority ? `<span class="topic-priority ${topic.priority}">${getPriorityText(topic.priority)}</span>` : ''}
                    </div>
                `).join('');
            } else {
                topicsList.innerHTML = '<p>Рекомендации будут доступны после анализа.</p>';
            }
            
        } catch (error) {
            console.error('Error submitting test:', error);
            alert('Произошла ошибка при отправке теста');
            testLoading.style.display = 'none';
            testQuestions.style.display = 'block';
        }
    }
    
    // Вспомогательные функции
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    function getPriorityText(priority) {
        const priorities = {
            'high': 'Высокий приоритет',
            'medium': 'Средний приоритет',
            'low': 'Низкий приоритет'
        };
        return priorities[priority] || priority;
    }
    
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
});

