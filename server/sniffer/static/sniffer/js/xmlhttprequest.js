function sendFormXhr(formData, url) {
    // 不刷新页面提交
    let xhr = new XMLHttpRequest()
    xhr.open('POST', url)
    xhr.send(formData)

    // 只是方便控制台检查是否提交成功
    xhr.onreadystatechange = function () {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            if (xhr.status === 200) {
                console.log('XHR submitted successfully')
            } else {
                console.log('Error submitting XHR')
            }
        }
    }
}

function fillFrom(id, dict) {
    var form = window.document.getElementById(id)
    var formData = new FormData(form)
    for (var key in dict) {
        formData.set(key, dict[key])
    }
    return formData
}
