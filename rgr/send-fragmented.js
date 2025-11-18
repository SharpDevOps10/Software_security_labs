const MAX_CHUNK_SIZE = 10;
const CHUNK_DELAY = 100;

const sendFragmented = (socket, data, loggerName) => {
  let i = 0;

  const intervalId = setInterval(() => {
    if (i >= data.length) {
      clearInterval(intervalId);
      return;
    }

    const chunk = data.substring(i, i + MAX_CHUNK_SIZE);
    i += MAX_CHUNK_SIZE;

    console.log(`${loggerName} (повільно) > надсилаю ${chunk.length} байт...`);

    socket.write(chunk);
  }, CHUNK_DELAY);
};

module.exports = {sendFragmented};