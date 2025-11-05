// State management
let currentGameState = null;

// Get URL parameters
const urlParams = new URLSearchParams(window.location.search);
const homeTeamName = urlParams.get('home') || 'HOME';
const awayTeamName = urlParams.get('away') || 'AWAY';

// Update team names
document.getElementById('home-team-name').textContent = homeTeamName;
document.getElementById('away-team-name').textContent = awayTeamName;

// Connect to SSE endpoint
const evtSource = new EventSource('/api/stream');

evtSource.onopen = () => {
    // Connection opened
};

evtSource.onerror = () => {
    // Connection error
};

evtSource.onmessage = (event) => {
    try {
        const data = JSON.parse(event.data);
        updateScoreboard(data);
    } catch (e) {
        console.error('Error parsing data:', e);
    }
};

function updateScoreboard(data) {
    // Update scores with animation only if changed
    updateElementIfChanged('home-score', data.home_score);
    updateElementIfChanged('away-score', data.away_score);
    
    // Update time with subtle animation
    updateTime(data.time_minutes, data.time_seconds);
    
    // Update period
    document.getElementById('period').textContent = data.period_name;
    
    // Update fouls
    updateElement('home-fouls', data.home_fouls);
    updateElement('away-fouls', data.away_fouls);
    
    // Update timeouts
    updateElement('home-timeouts', data.home_timeouts);
    updateElement('away-timeouts', data.away_timeouts);
    
    // Update shot clock
    updateShotClock(data.shot_clock);
    
    // Update game state (pause dot)
    updateGameState(data.game_state);
    
    // Store current state
    currentGameState = data;
}

function updateElementIfChanged(id, value) {
    const element = document.getElementById(id);
    if (!element) return;
    
    const currentValue = element.textContent;
    const newValue = value.toString();
    
    if (currentValue !== newValue) {
        element.textContent = newValue;
        element.classList.add('updated');
        setTimeout(() => element.classList.remove('updated'), 500);
    }
}

function updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function updateTime(minutes, seconds) {
    let timeStr;
    
    // If minutes contains a dot, it's already in seconds.tenths format
    if (minutes.includes('.')) {
        timeStr = minutes;
    } else {
        timeStr = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
    
    const timeElement = document.getElementById('time');
    if (!timeElement) return;
    
    if (timeElement.textContent !== timeStr) {
        timeElement.textContent = timeStr;
        timeElement.classList.add('updated');
        setTimeout(() => timeElement.classList.remove('updated'), 300);
    }
}

function updateShotClock(shotClock) {
    const element = document.getElementById('shot-clock');
    if (!element) return;
    
    const newValue = shotClock || '--';
    
    if (element.textContent !== newValue) {
        element.textContent = newValue;
        element.classList.add('updated');
        setTimeout(() => element.classList.remove('updated'), 400);
    }
}

function updateGameState(gameState) {
    const pauseDot = document.getElementById('pause-dot');
    if (!pauseDot) return;
    
    if (gameState === 'paused') {
        pauseDot.classList.add('visible');
    } else {
        pauseDot.classList.remove('visible');
    }
}

// Initial fetch to get current state
fetch('/api/game')
    .then(response => response.json())
    .then(data => {
        if (data) {
            updateScoreboard(data);
        }
    })
    .catch(error => {
        console.error('Error fetching initial state:', error);
    });
