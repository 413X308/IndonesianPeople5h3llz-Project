<html lang="vi"><head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trường THPT Phúc Lợi - Long Biên</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    
    <style>
        /* --- PHẦN CSS (STYLING) --- */
        
        /* Cấu hình chung */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        body {
            line-height: 1.6;
            color: #333;
            background-color: #f4f4f4;
        }

        .container {
            max-width: 1200px;
            margin: auto;
            padding: 0 20px;
        }

        /* Header & Thanh điều hướng */
        header {
            background: #004a99; /* Màu xanh chủ đạo của giáo dục */
            color: white;
            padding: 10px 0;
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        header .container {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo {
            display: flex;
            align-items: center;
        }

        .logo img {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            margin-right: 15px;
            border: 2px solid #fff;
        }

        .brand-name h1 {
            font-size: 1.4rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .brand-name p {
            font-size: 0.8rem;
            color: #ffcc00;
            font-style: italic;
        }

        nav ul {
            display: flex;
            list-style: none;
        }

        nav ul li {
            margin-left: 20px;
        }

        nav ul li a {
            color: white;
            text-decoration: none;
            font-weight: 600;
            font-size: 0.9rem;
            transition: 0.3s;
        }

        nav ul li a:hover {
            color: #ffcc00;
        }

        /* Banner (Hero Section) */
        .hero {
            height: 450px;
            background: linear-gradient(rgba(0,0,0,0.6), rgba(0,0,0,0.6)), 
                        url('https://images.unsplash.com/photo-1523050853063-913639473e5f?auto=format&fit=crop&w=1200&q=80') center/cover;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            text-align: center;
        }

        .hero-content h2 {
            font-size: 3rem;
            margin-bottom: 15px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }

        .btn {
            display: inline-block;
            background: #ce0000; /* Màu đỏ nổi bật */
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 30px;
            font-weight: bold;
            transition: 0.3s;
        }

        .btn:hover {
            background: #ffcc00;
            color: #333;
        }

        /* Tiêu đề các mục */
        .section-title {
            text-align: center;
            margin: 50px 0 30px;
            font-size: 2rem;
            color: #004a99;
            text-transform: uppercase;
            position: relative;
        }

        .section-title::after {
            content: '';
            display: block;
            width: 80px;
            height: 3px;
            background: #ffcc00;
            margin: 10px auto;
        }

        /* Giới thiệu */
        .about-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 40px;
            align-items: center;
            background: white;
            padding: 30px;
            border-radius: 10px;
        }

        .about-text p {
            margin-bottom: 15px;
            text-align: justify;
        }

        .about-img img {
            width: 100%;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        /* Tin tức */
        .news-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
        }

        .news-card {
            background: white;
            border-radius: 10px;
            overflow: hidden;
            transition: transform 0.3s;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        }

        .news-card:hover {
            transform: translateY(-5px);
        }

        .news-card img {
            width: 100%;
            height: 200px;
            object-fit: cover;
        }

        .news-card-body {
            padding: 20px;
        }

        .news-card-body h3 {
            font-size: 1.1rem;
            margin-bottom: 10px;
            color: #004a99;
        }

        /* Footer */
        footer {
            background: #1a1a1a;
            color: white;
            padding: 50px 0 20px;
            margin-top: 60px;
        }

        .footer-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 40px;
        }

        .footer-item h3 {
            color: #ffcc00;
            margin-bottom: 20px;
            border-left: 4px solid #ffcc00;
            padding-left: 10px;
        }

        .footer-item p {
            margin-bottom: 10px;
            font-size: 0.9rem;
            opacity: 0.8;
        }

        .footer-item i {
            margin-right: 10px;
            color: #ffcc00;
        }

        .footer-bottom {
            text-align: center;
            padding-top: 30px;
            margin-top: 30px;
            border-top: 1px solid #333;
            font-size: 0.8rem;
            color: #777;
        }

        /* Responsive di động */
        @media (max-width: 768px) {
            header .container { flex-direction: column; }
            nav ul { margin-top: 15px; }
            nav ul li { margin: 0 10px; }
            .about-grid { grid-template-columns: 1fr; }
            .hero-content h2 { font-size: 2rem; }
        }
    </style>
</head>
<body>

    <header>
        <div class="container">
            <div class="logo">
                <img src="https://via.placeholder.com/100/004a99/FFFFFF?text=PL" alt="Logo">
                <div class="brand-name">
                    <h1>THPT PHÚC LỢI</h1>
                    <p>Khát vọng vươn tới những tầm cao</p>
                </div>
            </div>
            <nav>
                <ul>
                    <li><a href="#">TRANG CHỦ</a></li>
                    <li><a href="#">GIỚI THIỆU</a></li>
                    <li><a href="#">TIN TỨC</a></li>
                    <li><a href="#">TUYỂN SINH</a></li>
                    <li><a href="#">LIÊN HỆ</a></li>
                </ul>
            </nav>
        </div>
    </header>

    <section class="hero">
        <div class="hero-content">
            <h2>HÀNH TRÌNH TRI THỨC</h2>
            <p>Nơi ươm mầm tài năng và định hướng tương lai cho thế hệ trẻ.</p>
            <br>
            <a href="#" class="btn">KHÁM PHÁ NGAY</a>
        </div>
    </section>

    <div class="container">
        <h2 class="section-title">Về chúng tôi</h2>
        <section class="about-grid">
            <div class="about-text">
                <p><strong>Trường THPT Phúc Lợi</strong> tọa lạc tại quận Long Biên, Hà Nội. Với lịch sử hình thành và phát triển, nhà trường đã khẳng định được vị thế trong hệ thống giáo dục Thủ đô.</p>
                <p>Chúng tôi cam kết mang lại môi trường học tập an toàn, thân thiện và sáng tạo. Đội ngũ giáo viên giàu kinh nghiệm, tâm huyết luôn sẵn sàng đồng hành cùng học sinh trong mọi thử thách.</p>
                <p>Cơ sở vật chất hiện đại với các phòng thí nghiệm, thư viện và khu thể thao đạt chuẩn, đáp ứng nhu cầu học tập và giải trí của các em.</p>
            </div>
            <div class="about-img">
                <img src="https://images.unsplash.com/photo-1541339907198-e08756ebafe3?auto=format&amp;fit=crop&amp;w=600&amp;q=80" alt="Trường học">
            </div>
        </section>

        <h2 class="section-title">Tin tức nổi bật</h2>
        <section class="news-grid">
            <div class="news-card">
                <img src="https://images.unsplash.com/photo-1511629091441-ee46146481b6?auto=format&amp;fit=crop&amp;w=400&amp;q=80" alt="Tin 1">
                <div class="news-card-body">
                    <h3>Kế hoạch thi học kỳ II năm học 2025-2026</h3>
                    <p>Thông báo lịch thi chi tiết cho toàn thể học sinh các khối lớp...</p>
                </div>
            </div>
            <div class="news-card">
                <img src="https://images.unsplash.com/photo-1529333166437-7750a6dd5a70?auto=format&amp;fit=crop&amp;w=400&amp;q=80" alt="Tin 2">
                <div class="news-card-body">
                    <h3>Hội thi văn nghệ chào mừng ngày 26/3</h3>
                    <p>Các chi đoàn sôi nổi tập luyện và trình diễn những tiết mục đặc sắc...</p>
                </div>
            </div>
            <div class="news-card">
                <img src="https://images.unsplash.com/photo-1503676260728-1c00da094a0b?auto=format&amp;fit=crop&amp;w=400&amp;q=80" alt="Tin 3">
                <div class="news-card-body">
                    <h3>Tư vấn hướng nghiệp cho học sinh khối 12</h3>
                    <p>Đón đoàn chuyên gia từ các trường Đại học top đầu về tư vấn tuyển sinh...</p>
                </div>
            </div>
        </section>
    </div>

    <footer>
        <div class="container footer-grid">
            <div class="footer-item">
                <h3>THÔNG TIN LIÊN HỆ</h3>
                <p><i class="fas fa-map-marker-alt"></i> Địa chỉ: Phố Phúc Lợi, Long Biên, Hà Nội</p>
                <p><i class="fas fa-phone"></i>696969</p>
                <p><i class="fas fa-envelope"></i> Email: c3phucloi@hanoi.edu.vn</p>
            </div>
            <div class="footer-item">
                <h3>LIÊN KẾT NHANH</h3>
                <p><a href="https://c3phucloi.edu.vn/" style="color:white; text-decoration:none;">Cổng thông tin học sinh</a></p>
                <p><a href="https://c3phucloi.edu.vn/" style="color:white; text-decoration:none;">Thời khóa biểu</a></p>
                <p><a href="#" style="color:white; text-decoration:none;">Thư viện ảnh</a></p>
            </div>
            <div class="footer-item">
                <h3>THEO DÕI CHÚNG TÔI</h3>
                <div style="font-size: 1.5rem;">
                    <a href="#" style="color: #4267B2; margin-right: 15px;"><i class="fab fa-facebook"></i></a>
                    <a href="#" style="color: #FF0000; margin-right: 15px;"><i class="fab fa-youtube"></i></a>
                    <a href="#" style="color: #1DA1F2;"><i class="fab fa-twitter"></i></a>
                </div>
            </div>
        </div>
        <div class="footer-bottom">
            © 2026 Bản quyền thuộc về Trường THPT Phúc Lợi. Thiết kế bởi AI Assistant.
        </div>
    </footer>


</body></html>
