// Скрипт страницы проверки доступа
document.getElementById('truthForm').addEventListener('submit', function() {
    document.getElementById('loading').style.display = 'block';
});

// Сохраняем состояние формы в localStorage
function saveFormState() {
    const formData = {
        src: document.getElementById('src').value,
        dst: document.getElementById('dst').value,
        port: document.getElementById('port').value,
        filter: document.getElementById('filter').value
    };
    try {
        localStorage.setItem('checkFormState', JSON.stringify(formData));
    } catch(e) {
        console.log('Error saving form state:', e);
    }
}

// Восстанавливаем состояние формы
function restoreFormState() {
    // Если параметры пришли в адресе, форму уже заполнил сервер.
    // Сохраненные значения не должны подменять запрос, по которому показан результат
    if (window.location.search.length > 1) {
        saveFormState();
        return;
    }

    try {
        const saved = localStorage.getItem('checkFormState');
        if (saved) {
            const formData = JSON.parse(saved);
            document.getElementById('src').value = formData.src || '';
            document.getElementById('dst').value = formData.dst || '';
            document.getElementById('port').value = formData.port || '';
            
            if (formData.filter) {
                const filterSelect = document.getElementById('filter');
                for (let i = 0; i < filterSelect.options.length; i++) {
                    if (filterSelect.options[i].value === formData.filter) {
                        filterSelect.selectedIndex = i;
                        break;
                    }
                }
            }
        }
    } catch(e) {
        console.log('Error restoring form state:', e);
    }
}

// Навешиваем обработчики на все поля формы
document.querySelectorAll('#truthForm input, #truthForm select').forEach(function(element) {
    element.addEventListener('change', saveFormState);
    element.addEventListener('input', saveFormState);
});

// Восстанавливаем состояние при загрузке
document.addEventListener('DOMContentLoaded', restoreFormState);
