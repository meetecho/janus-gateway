/* background page, responsible for actually choosing media */
chrome.runtime.onConnect.addListener(function (channel) {
    channel.onMessage.addListener(function (message) {
        switch(message.type) {
        case 'getScreen':
            var pending = chrome.desktopCapture.chooseDesktopMedia(message.options || ['screen', 'window'], 
                                                                   channel.sender.tab, function (streamid) {
                // communicate this string to the app so it can call getUserMedia with it
                message.type = 'gotScreen';
                message.sourceId = streamid;
                channel.postMessage(message);
            });
            // let the app know that it can cancel the timeout
            message.type = 'getScreenPending';
            message.request = pending;
            channel.postMessage(message);
            break;
        case 'cancelGetScreen':
            chrome.desktopCapture.cancelChooseDesktopMedia(message.request);
            message.type = 'canceledGetScreen';
            channel.postMessage(message);
            break;
        }
    });
});
