/**
 * Anti-cheat система для контрольных работ
 * ВНИМАНИЕ: Вся критическая логика проверки на сервере!
 * Этот скрипт только отслеживает события и отправляет их на сервер
 */
(function() {
    'use strict';
    
    var _0x4d6f = (function() {
        var _0x1a2b = ['\x6c\x6f\x67', '\x74\x61\x62\x53\x77\x69\x74\x63\x68\x65\x73', '\x76\x69\x6f\x6c\x61\x74\x69\x6f\x6e\x73', '\x63\x6f\x70\x79', '\x73\x63\x72\x65\x65\x6e\x73\x68\x6f\x74\x41\x74\x74\x65\x6d\x70\x74\x73', '\x73\x68\x6f\x77\x44\x65\x73\x6b\x74\x6f\x70\x41\x74\x74\x65\x6d\x70\x74\x73', '\x66\x75\x6c\x6c\x73\x63\x72\x65\x65\x6e\x45\x78\x69\x74\x73', '\x72\x65\x6d\x61\x69\x6e\x69\x6e\x67', '\x74\x69\x6d\x65\x73\x74\x61\x6d\x70', '\x61\x74\x74\x65\x6d\x70\x74\x5f', '\x5f\x76\x69\x6f\x6c\x61\x74\x69\x6f\x6e\x73', '\x5f\x72\x65\x6d\x61\x69\x6e\x69\x6e\x67', '\x73\x65\x74\x49\x74\x65\x6d', '\x67\x65\x74\x49\x74\x65\x6d', '\x70\x61\x72\x73\x65', '\x73\x74\x72\x69\x6e\x67\x69\x66\x79', '\x6e\x6f\x77', '\x6d\x61\x78', '\x30\x30', '\x70\x61\x64\x53\x74\x61\x72\x74', '\x3a', '\x53\x74\x72\x69\x6e\x67', '\x61\x6c\x65\x72\x74', '\x73\x75\x62\x6d\x69\x74', '\x61\x70\x70\x65\x6e\x64', '\x63\x72\x65\x61\x74\x65\x45\x6c\x65\x6d\x65\x6e\x74', '\x68\x69\x64\x64\x65\x6e', '\x74\x79\x70\x65', '\x6e\x61\x6d\x65', '\x76\x61\x6c\x75\x65', '\x72\x65\x6d\x6f\x76\x65\x49\x74\x65\x6d', '\x61\x64\x64\x45\x76\x65\x6e\x74\x4c\x69\x73\x74\x65\x6e\x65\x72', '\x70\x72\x65\x76\x65\x6e\x74\x44\x65\x66\x61\x75\x6c\x74', '\x6b\x65\x79\x64\x6f\x77\x6e', '\x6b\x65\x79', '\x74\x6f\x4c\x6f\x77\x65\x72\x43\x61\x73\x65', '\x63\x74\x72\x6c\x4b\x65\x79', '\x73\x68\x69\x66\x74\x4b\x65\x79', '\x6d\x65\x74\x61\x4b\x65\x79', '\x63\x6f\x6e\x74\x65\x78\x74\x6d\x65\x6e\x75', '\x63\x6c\x69\x63\x6b', '\x68\x69\x64\x64\x65\x6e', '\x62\x6c\x75\x72', '\x76\x69\x73\x69\x62\x69\x6c\x69\x74\x79\x63\x68\x61\x6e\x67\x65', '\x63\x6f\x70\x79', '\x63\x75\x74', '\x66\x75\x6c\x6c\x73\x63\x72\x65\x65\x6e\x63\x68\x61\x6e\x67\x65', '\x66\x75\x6c\x6c\x73\x63\x72\x65\x65\x6e\x45\x6c\x65\x6d\x65\x6e\x74', '\x72\x65\x71\x75\x65\x73\x74\x46\x75\x6c\x6c\x73\x63\x72\x65\x65\x6e', '\x64\x6f\x63\x75\x6d\x65\x6e\x74\x45\x6c\x65\x6d\x65\x6e\x74', '\x6f\x6e\x63\x65', '\x69\x6e\x69\x74', '\x72\x65\x61\x64\x79\x53\x74\x61\x74\x65', '\x6c\x6f\x61\x64\x69\x6e\x67', '\x44\x4f\x4d\x43\x6f\x6e\x74\x65\x6e\x74\x4c\x6f\x61\x64\x65\x64'];
        return function(index) { return _0x1a2b[index - 1]; };
    })();

    var CONFIG = window.ANTICHEAT_CONFIG || {};
    var labIsTest = CONFIG.isTest || false;
    var testDurationMinutes = CONFIG.duration || 0;
    var attemptId = CONFIG.attemptId || 0;
    var serverStartTime = CONFIG.serverStartTime || Date.now();
    var remainingTime = CONFIG.remainingTime || null;

    if (!labIsTest) return;

    var violationsKey = _0x4d6f(10) + attemptId + _0x4d6f(11);
    var remainingTimeKey = _0x4d6f(10) + attemptId + _0x4d6f(12);
    var sessionStartKey = _0x4d6f(10) + attemptId + '_session_start';
    var pageLoadKey = _0x4d6f(10) + attemptId + '_page_load';

    // Debounce настройки
    var TAB_SWITCH_DEBOUNCE = 3000; // 3 секунды между нарушениями
    var DEVTOOLS_DEBOUNCE = 5000; // 5 секунд для DevTools
    var SCREENSHOT_DEBOUNCE = 2000; // 2 секунды для скриншотов
    
    var lastTabSwitchTime = 0;
    var lastDevToolsCheck = 0;
    var lastScreenshotTime = 0;
    var isInitialLoad = true;
    var pageLoadCount = 0;

    var _state = {
        tabSwitches: 0,
        copy: false,
        screenshotAttempts: 0,
        showDesktopAttempts: 0,
        fullscreenExits: 0,
        trackingActive: false,
        initialLoadComplete: false,
        lastHeartbeat: Date.now(),
        timeRemaining: 0,
        timerInterval: null
    };

    // Проверяем, новая ли это сессия
    var currentSessionStart = Date.now();
    var savedSessionStart = localStorage.getItem(sessionStartKey);
    var isNewSession = !savedSessionStart || (currentSessionStart - parseInt(savedSessionStart)) > 10000; // 10 секунд
    
    if (isNewSession) {
        // Это новая сессия - сбрасываем все нарушения
        console.log('New session detected, resetting violations');
        _state.tabSwitches = 0;
        _state.copy = false;
        _state.screenshotAttempts = 0;
        _state.showDesktopAttempts = 0;
        _state.fullscreenExits = 0;
        
        // Сохраняем время начала сессии
        localStorage.setItem(sessionStartKey, currentSessionStart.toString());
        localStorage.setItem(pageLoadKey, '1');
        pageLoadCount = 1;
        
        // Сохраняем сброшенное состояние
        saveViolations();
    } else {
        // Это та же сессия - загружаем сохраненные нарушения
        try {
            var savedViolations = localStorage.getItem(violationsKey);
            if (savedViolations) {
                var data = JSON.parse(savedViolations);
                _state.tabSwitches = data.t || 0;
                _state.copy = (data.c === 1);
                _state.screenshotAttempts = data.s || 0;
                _state.showDesktopAttempts = data.d || 0;
                _state.fullscreenExits = data.f || 0;
                console.log('Loaded existing violations:', _state.tabSwitches);
            }
            
            // Увеличиваем счетчик загрузок страницы
            var loads = localStorage.getItem(pageLoadKey);
            pageLoadCount = loads ? parseInt(loads) + 1 : 1;
            localStorage.setItem(pageLoadKey, pageLoadCount.toString());
            
            // Если страница перезагружалась много раз - не считаем это нарушениями
            console.log('Page load count:', pageLoadCount);
        } catch(e) {
            console.error('Error loading violations:', e);
        }
    }

    function saveViolations() {
        try {
            var data = {
                t: _state.tabSwitches,
                c: _state.copy ? 1 : 0,
                s: _state.screenshotAttempts,
                d: _state.showDesktopAttempts,
                f: _state.fullscreenExits,
                h: _state.lastHeartbeat
            };
            localStorage.setItem(violationsKey, JSON.stringify(data));
        } catch(e) {}
    }

    function formatTime(seconds) {
        var mins = Math.floor(seconds / 60);
        var secs = seconds % 60;
        return String(mins).padStart(2, '0') + ':' + String(secs).padStart(2, '0');
    }

    function updateTimerDisplay() {
        var timerBox = document.getElementById('timerBox');
        var timeRemainingSpan = document.getElementById('timeRemaining');
        
        if (!timerBox || !timeRemainingSpan) return;
        
        if (_state.timeRemaining <= 0) {
            timeRemainingSpan.textContent = '00:00';
            timerBox.classList.add('warning');
            return;
        }
        
        timeRemainingSpan.textContent = formatTime(_state.timeRemaining);
        
        if (_state.timeRemaining <= 60) {
            timerBox.classList.add('warning');
        } else {
            timerBox.classList.remove('warning');
        }
    }

    function startTimer() {
        var timerBox = document.getElementById('timerBox');
        if (!timerBox) return;
        
        timerBox.style.display = 'block';
        
        if (remainingTime !== null) {
            _state.timeRemaining = remainingTime;
        } else if (testDurationMinutes > 0) {
            var elapsedSeconds = Math.floor((Date.now() - serverStartTime) / 1000);
            var totalSeconds = testDurationMinutes * 60;
            _state.timeRemaining = Math.max(0, totalSeconds - elapsedSeconds);
        } else {
            return;
        }
        
        updateTimerDisplay();
        
        if (_state.timerInterval) {
            clearInterval(_state.timerInterval);
        }
        
        _state.timerInterval = setInterval(function() {
            if (_state.timeRemaining > 0) {
                _state.timeRemaining--;
                updateTimerDisplay();
                
                try {
                    localStorage.setItem(remainingTimeKey, _state.timeRemaining.toString());
                } catch(e) {}
                
                if (_state.timeRemaining <= 0) {
                    clearInterval(_state.timerInterval);
                    setTimeout(function() {
                        alert('Время вышло! Работа будет завершена автоматически.');
                        var quizForm = document.getElementById('quizForm');
                        if (quizForm) {
                            quizForm.submit();
                        }
                    }, 500);
                }
            }
        }, 1000);
    }

    function sendHeartbeat() {
        _state.lastHeartbeat = Date.now();
        saveViolations();
        
        if (CONFIG.attemptId) {
            fetch('/anticheat-heartbeat/' + CONFIG.attemptId, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    t: _state.tabSwitches,
                    c: _state.copy ? 1 : 0,
                    s: _state.screenshotAttempts,
                    d: _state.showDesktopAttempts,
                    f: _state.fullscreenExits,
                    pc: pageLoadCount
                })
            }).catch(function() {});
        }
    }

    var heartbeatInterval = setInterval(sendHeartbeat, 5000);

    function activateTracking() {
        if (_state.initialLoadComplete) return;
        _state.initialLoadComplete = true;
        _state.trackingActive = true;
        isInitialLoad = false;
        console.log('Anti-cheat tracking activated');
    }

    function trackTabSwitches() {
        // Даем время на инициализацию
        setTimeout(function() {
            isInitialLoad = false;
            activateTracking();
        }, 3000);
        
        document.addEventListener('click', function() {
            if (isInitialLoad) {
                isInitialLoad = false;
                activateTracking();
            }
        }, {once: true});
        
        document.addEventListener('keydown', function() {
            if (isInitialLoad) {
                isInitialLoad = false;
                activateTracking();
            }
        }, {once: true});

        var visibilityChangeHandled = false;
        
        document.addEventListener('visibilitychange', function() {
            if (!_state.trackingActive || isInitialLoad) {
                console.log('Ignoring visibility change - tracking not active');
                return;
            }
            
            if (document.hidden) {
                var now = Date.now();
                
                if (now - lastTabSwitchTime > TAB_SWITCH_DEBOUNCE) {
                    _state.tabSwitches++;
                    lastTabSwitchTime = now;
                    visibilityChangeHandled = true;
                    saveViolations();
                    updateViolationsDisplay();
                    sendHeartbeat();
                    console.log('⚠️ Tab switch detected. Total:', _state.tabSwitches);
                }
            } else {
                // Сбрасываем флаг когда возвращаемся
                setTimeout(function() {
                    visibilityChangeHandled = false;
                }, 500);
            }
        });

        window.addEventListener('blur', function() {
            if (!_state.trackingActive || isInitialLoad) {
                console.log('Ignoring blur - tracking not active');
                return;
            }
            
            // Если это было вызвано переключением вкладки - пропускаем
            if (document.hidden) {
                console.log('Blur caused by tab switch - ignoring');
                return;
            }
            
            var now = Date.now();
            
            if (now - lastTabSwitchTime > TAB_SWITCH_DEBOUNCE) {
                _state.tabSwitches++;
                lastTabSwitchTime = now;
                saveViolations();
                updateViolationsDisplay();
                sendHeartbeat();
                console.log('⚠️ Window blur detected. Total:', _state.tabSwitches);
            }
        });
        
        // Отслеживание переключения окон
        window.addEventListener('focus', function() {
            console.log('Window focused');
        });
    }

    function trackCopy() {
        document.addEventListener('copy', function(e) {
            if (!_state.trackingActive) return;
            
            if (!_state.copy) {
                _state.copy = true;
                saveViolations();
                showViolationMessage('\u26a0\ufe0f\u2009\u041e\u0431\u043d\u0430\u0440\u0443\u0436\u0435\u043d\u043e\u2009\u043a\u043e\u043f\u0438\u0440\u043e\u0432\u0430\u043d\u0438\u0435!');
                sendHeartbeat();
            }
        });

        document.addEventListener('cut', function(e) {
            if (!_state.trackingActive) return;
            
            if (!_state.copy) {
                _state.copy = true;
                saveViolations();
                showViolationMessage('\u26a0\ufe0f\u2009\u041e\u0431\u043d\u0430\u0440\u0443\u0436\u0435\u043d\u043e\u2009\u0432\u044b\u0440\u0435\u0437\u0430\u043d\u0438\u0435\u2009\u0442\u0435\u043a\u0441\u0442\u0430!');
                sendHeartbeat();
            }
        });
    }

    function trackHotkeys() {
        document.addEventListener('keydown', function(e) {
            if (!_state.trackingActive) return;
            
            var key = e.key.toLowerCase();
            var now = Date.now();
            
            if (e.key === 'PrintScreen') {
                e.preventDefault();
                if (now - lastScreenshotTime > SCREENSHOT_DEBOUNCE) {
                    _state.screenshotAttempts++;
                    lastScreenshotTime = now;
                    saveViolations();
                    updateViolationsDisplay();
                    showViolationMessage('\u26a0\ufe0f\u2009\u0421\u043a\u0440\u0438\u043d\u0448\u043e\u0442!');
                    sendHeartbeat();
                    console.log('Screenshot attempted. Total:', _state.screenshotAttempts);
                }
            }
            
            // Mac screenshot shortcuts
            if ((e.metaKey && e.shiftKey && (key === '3' || key === '4' || key === '5')) ||
                (e.ctrlKey && e.shiftKey && (key === '3' || key === '4' || key === '5'))) {
                e.preventDefault();
                if (now - lastScreenshotTime > SCREENSHOT_DEBOUNCE) {
                    _state.screenshotAttempts++;
                    lastScreenshotTime = now;
                    saveViolations();
                    updateViolationsDisplay();
                    showViolationMessage('\u26a0\ufe0f\u2009\u0421\u043a\u0440\u0438\u043d\u0448\u043e\u0442!');
                    sendHeartbeat();
                }
            }
            
            // Windows Snipping Tool
            if (e.metaKey && e.shiftKey && key === 's') {
                e.preventDefault();
                if (now - lastScreenshotTime > SCREENSHOT_DEBOUNCE) {
                    _state.screenshotAttempts++;
                    lastScreenshotTime = now;
                    saveViolations();
                    updateViolationsDisplay();
                    showViolationMessage('\u26a0\ufe0f\u2009\u0421\u043a\u0440\u0438\u043d\u0448\u043e\u0442!');
                    sendHeartbeat();
                }
            }
        });
    }

    function trackFullscreen() {
        var fullscreenChangeHandler = function() {
            var isFullscreen = document.fullscreenElement || 
                              document.webkitFullscreenElement || 
                              document.mozFullScreenElement ||
                              document.msFullscreenElement;
            
            if (!isFullscreen && _state.trackingActive && !isInitialLoad) {
                var now = Date.now();
                if (now - lastTabSwitchTime > TAB_SWITCH_DEBOUNCE) {
                    _state.fullscreenExits++;
                    lastTabSwitchTime = now;
                    saveViolations();
                    sendHeartbeat();
                    console.log('Fullscreen exit detected');
                }
            }
        };
        
        document.addEventListener('fullscreenchange', fullscreenChangeHandler);
        document.addEventListener('webkitfullscreenchange', fullscreenChangeHandler);
        document.addEventListener('mozfullscreenchange', fullscreenChangeHandler);
        document.addEventListener('MSFullscreenChange', fullscreenChangeHandler);
    }

    function updateViolationsDisplay() {
        var panel = document.getElementById('violationsPanel');
        if (!panel) return;

        var total = _state.tabSwitches + _state.screenshotAttempts + _state.showDesktopAttempts;
        if (total > 0) {
            panel.style.display = 'block';
            var countSpan = document.getElementById('violationsCount');
            if (countSpan) {
                countSpan.textContent = total;
            }
            panel.innerHTML = '\u26a0\ufe0f\u2009\u041d\u0430\u0440\u0443\u0448\u0435\u043d\u0438\u044f:\u2009<span id="violationsCount">' + total + '</span>\u2009(\u0432\u043a\u043b\u0430\u0434\u043a\u0438:\u2009' + _state.tabSwitches + ',\u2009\u0441\u043a\u0440\u0438\u043d\u0448\u043e\u0442\u044b:\u2009' + _state.screenshotAttempts + ')';
        }
    }

    function showViolationMessage(message) {
        var panel = document.getElementById('violationsPanel');
        if (!panel) return;

        var original = panel.innerHTML;
        panel.innerHTML = message;
        panel.style.display = 'block';

        setTimeout(function() {
            updateViolationsDisplay();
        }, 2000);
    }

    function disableContextMenu() {
        document.addEventListener('contextmenu', function(e) {
            e.preventDefault();
            return false;
        });
    }

    function disableDevTools() {
        // Блокировка горячих клавиш DevTools
        document.addEventListener('keydown', function(e) {
            if (!_state.trackingActive) return;
            
            var blocked = false;
            var now = Date.now();
            
            // F12
            if (e.key === 'F12') blocked = true;
            // Ctrl+Shift+I / Cmd+Option+I
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'i') blocked = true;
            // Ctrl+Shift+J / Cmd+Option+J
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'j') blocked = true;
            // Ctrl+U / Cmd+U
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'u') blocked = true;
            // Ctrl+S / Cmd+S
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') blocked = true;
            // Ctrl+P / Cmd+P
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'p') blocked = true;
            
            if (blocked) {
                e.preventDefault();
                e.stopPropagation();
                console.log('DevTools hotkey blocked:', e.key);
                return false;
            }
        });
    }

    function disableTextSelection() {
        document.body.style.userSelect = 'none';
        document.body.style.webkitUserSelect = 'none';
        document.body.style.mozUserSelect = 'none';
        document.body.style.msUserSelect = 'none';
    }

    function requestFullscreen() {
        var elem = document.documentElement;
        
        setTimeout(function() {
            if (elem.requestFullscreen) {
                elem.requestFullscreen().catch(function(err) {
                    console.log('Fullscreen request failed:', err);
                });
            } else if (elem.webkitRequestFullscreen) {
                elem.webkitRequestFullscreen();
            } else if (elem.msRequestFullscreen) {
                elem.msRequestFullscreen();
            }
        }, 1000);
    }

    function preventPrint() {
        window.addEventListener('beforeprint', function(e) {
            if (!_state.trackingActive) return;
            
            _state.screenshotAttempts++;
            saveViolations();
            updateViolationsDisplay();
            sendHeartbeat();
            console.log('Print attempted');
        });
    }

    function init() {
        console.log('Anti-cheat initializing...');
        console.log('Current violations before init:', _state.tabSwitches);
        
        // Загружаем сохраненное время
        try {
            var savedTime = localStorage.getItem(remainingTimeKey);
            if (savedTime) {
                remainingTime = parseInt(savedTime);
            }
        } catch(e) {}
        
        trackTabSwitches();
        trackCopy();
        trackHotkeys();
        trackFullscreen();
        preventPrint();
        
        disableContextMenu();
        disableTextSelection();
        disableDevTools();
        
        requestFullscreen();
        
        updateViolationsDisplay();
        startTimer();

        var quizForm = document.getElementById('quizForm');
        if (quizForm) {
            quizForm.addEventListener('submit', function(e) {
                var tsInput = document.createElement('input');
                tsInput.type = 'hidden';
                tsInput.name = 'client_timestamp';
                tsInput.value = Date.now().toString();
                this.appendChild(tsInput);

                var hashInput = document.createElement('input');
                hashInput.type = 'hidden';
                hashInput.name = 'client_state_hash';
                hashInput.value = btoa(JSON.stringify({
                    t: _state.tabSwitches,
                    c: _state.copy ? 1 : 0,
                    s: _state.screenshotAttempts
                }));
                this.appendChild(hashInput);

                if (_state.timerInterval) {
                    clearInterval(_state.timerInterval);
                }
                if (heartbeatInterval) {
                    clearInterval(heartbeatInterval);
                }

                // Очищаем все данные при отправке
                localStorage.removeItem(violationsKey);
                localStorage.removeItem(remainingTimeKey);
                localStorage.removeItem(sessionStartKey);
                localStorage.removeItem(pageLoadKey);
                
                sendHeartbeat();
            }, true);
        }
        
        window.addEventListener('beforeunload', function(e) {
            if (_state.trackingActive && _state.timeRemaining > 0) {
                var message = 'Вы уверены, что хотите покинуть страницу? Прогресс может быть потерян.';
                e.returnValue = message;
                return message;
            }
        });
        
        console.log('Anti-cheat initialized. Tracking will activate in 3 seconds...');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();