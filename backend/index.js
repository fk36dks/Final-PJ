const express = require("express");
const app = express();
const PORT = process.env.PORT || 5000;  // 기본 포트를 5000으로 변경

// 샘플 상품 데이터
const products = [
  { id: 1, name: "노트북", price: 1200000 },
  { id: 2, name: "마우스", price: 25000 },
  { id: 3, name: "키보드", price: 45000 }
];

// API 엔드포인트
app.get("/products", (req, res) => {
  res.json(products);
});

app.listen(PORT, () => {
  console.log(`Backend API server running on port ${PORT}`);
});

