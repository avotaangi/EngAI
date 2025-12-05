// Media Center JavaScript
document.addEventListener('DOMContentLoaded', function() {
    const mediaPage = document.querySelector('.media-page');
    if (!mediaPage) return;
    
    const endpoint = mediaPage.dataset.mediaEndpoint;
    const defaultCategory = mediaPage.dataset.defaultCategory || 'movies';
    const grid = document.getElementById('mediaPageGrid');
    const status = document.getElementById('mediaPageStatus');
    const refreshBtn = document.getElementById('mediaPageRefresh');
    const filterButtons = document.querySelectorAll('.media-filter button');
    
    let currentCategory = defaultCategory;
    
    // Загрузка контента
    function loadMedia(category) {
        status.textContent = 'Загружаем подборку...';
        status.style.display = 'block';
        grid.innerHTML = '';
        
        fetch(`${endpoint}?category=${category}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Ошибка загрузки');
                }
                return response.json();
            })
            .then(data => {
                status.style.display = 'none';
                
                if (data.error) {
                    status.textContent = data.error;
                    status.style.display = 'block';
                    status.style.color = '#ff4757';
                    return;
                }
                
                if (!data.items || data.items.length === 0) {
                    status.textContent = 'Контент не найден';
                    status.style.display = 'block';
                    return;
                }
                
                renderMediaCards(data.items);
            })
            .catch(error => {
                console.error('Ошибка:', error);
                status.textContent = 'Не удалось загрузить подборку. Попробуйте позже.';
                status.style.display = 'block';
                status.style.color = '#ff4757';
            });
    }
    
    // Рендеринг карточек
    function renderMediaCards(items) {
        grid.innerHTML = '';
        
        items.forEach(item => {
            const card = createMediaCard(item);
            grid.appendChild(card);
        });
    }
    
    // Создание карточки
    function createMediaCard(item) {
        const card = document.createElement('div');
        card.className = 'media-card';
        card.setAttribute('data-media-id', item.id);
        card.setAttribute('data-media-type', item.type || 'movie');
        
        const imageUrl = item.cover || item.poster_url || '';
        const rating = item.rating || 0;
        const genres = item.genres || [];
        const releaseDate = item.release_date || item.premiered || '';
        const summary = item.summary || item.overview || 'Описание недоступно';
        
        const dateFormatted = releaseDate ? new Date(releaseDate).getFullYear() : '';
        
        card.innerHTML = `
            <div class="media-card-image">
                ${imageUrl ? 
                    `<img src="${imageUrl}" alt="${item.title}" loading="lazy" onerror="this.parentElement.innerHTML='<i class=\\'bi bi-film\\'></i>'">` :
                    '<i class="bi bi-film"></i>'
                }
            </div>
            <div class="media-card-content">
                <div class="media-card-header">
                    <h3 class="media-card-title">${escapeHtml(item.title)}</h3>
                    ${rating > 0 ? `
                        <div class="media-card-rating">
                            <i class="bi bi-star-fill"></i>
                            ${rating.toFixed(1)}
                        </div>
                    ` : ''}
                </div>
                <p class="media-card-summary">${escapeHtml(summary)}</p>
                <div class="media-card-footer">
                    <div class="media-card-genres">
                        ${genres.slice(0, 2).map(genre => 
                            `<span class="media-card-genre">${escapeHtml(genre)}</span>`
                        ).join('')}
                    </div>
                    ${dateFormatted ? `<span class="media-card-date">${dateFormatted}</span>` : ''}
                </div>
            </div>
        `;
        
        // Обработчик клика
        card.addEventListener('click', function() {
            const mediaType = item.type === 'tv' ? 'tv' : 'movie';
            const mediaId = item.tmdb_id || item.id;
            window.location.href = `/cards/media/${mediaType}/${mediaId}/`;
        });
        
        return card;
    }
    
    // Экранирование HTML
    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    
    // Обработчики фильтров
    filterButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const category = this.dataset.mediaFilter;
            
            // Обновляем активное состояние
            filterButtons.forEach(b => {
                b.classList.remove('active');
                b.setAttribute('aria-selected', 'false');
            });
            this.classList.add('active');
            this.setAttribute('aria-selected', 'true');
            
            currentCategory = category;
            loadMedia(category);
        });
    });
    
    // Обработчик обновления
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadMedia(currentCategory);
        });
    }
    
    // Начальная загрузка
    loadMedia(currentCategory);
});

