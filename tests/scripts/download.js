// res.file(): fixed-length streaming download from the allowed read dir
const res = HTTP.send;
res.file("data/small.txt");
