<?php
/**
 * ============================================================================
 * TELEGRAM CHANNEL BACKEND API (PHP + FIREBASE REALTIME DATABASE REST API)
 * ============================================================================
 * Tương tác trực tiếp với Firebase Realtime Database qua REST API JSON (cURL).
 * Mật khẩu mã hóa SHA-256 an toàn.
 * Chống XSS (htmlspecialchars), Rate Limiting (2s/tin), Phân quyền Admin/Pending.
 * ============================================================================
 */

error_reporting(E_ALL & ~E_NOTICE);
ini_set('display_errors', 0);

// Headers chuẩn REST API & CORS
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-User-Token');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// ============================================================================
// 1. CẤU HÌNH FIREBASE REALTIME DATABASE REST API URL
// ============================================================================
// Thay thế bằng URL Firebase của bạn (hoặc ghi đè qua file config/header)
$firebaseDbUrl = "https://YOUR_FIREBASE_PROJECT_ID-default-rtdb.firebaseio.com";
$firebaseDbUrl = rtrim($firebaseDbUrl, '/');

// Thư mục cache dự phòng nếu Firebase URL chưa được thay đổi
$cacheDir = __DIR__ . '/data';
if (!is_dir($cacheDir)) {
    @mkdir($cacheDir, 0755, true);
    @file_put_contents($cacheDir . '/.htaccess', "Deny from all\n");
}

// Tài khoản Admin mặc định
define('DEFAULT_ADMIN_USER', 'admin');
define('DEFAULT_ADMIN_PASS', '0386744127');
define('DEFAULT_ADMIN_HASH', '267cae80ce3fea93e60a755bf0ee2f7f7f2a1c2198a48c93a0730dff6b575a77'); // SHA-256 của 0386744127

/**
 * Hàm cURL gọi trực tiếp tới Firebase Realtime Database REST API
 */
function firebaseRestCall($endpoint, $method = 'GET', $data = null) {
    global $firebaseDbUrl;

    // Kiểm tra nếu là URL placeholder chưa thay thế
    $isPlaceholder = (strpos($firebaseDbUrl, 'YOUR_FIREBASE_PROJECT_ID') !== false);
    if ($isPlaceholder) {
        return localCacheFallbackCall($endpoint, $method, $data);
    }

    $url = $firebaseDbUrl . '/' . ltrim($endpoint, '/') . '.json';

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($ch, CURLOPT_TIMEOUT, 6);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);

    if ($data !== null) {
        $payload = is_string($data) ? $data : json_encode($data, JSON_UNESCAPED_UNICODE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json; charset=utf-8',
            'Content-Length: ' . strlen($payload)
        ]);
    } else {
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json; charset=utf-8'
        ]);
    }

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error || $httpCode >= 400 || $response === false) {
        // Dự phòng bộ nhớ đệm nếu Firebase tạm thời không truy cập được
        return localCacheFallbackCall($endpoint, $method, $data);
    }

    $decoded = json_decode($response, true);
    return ['success' => true, 'data' => $decoded, 'code' => $httpCode];
}

/**
 * Bộ nhớ đệm dự phòng mượt mà khi Firebase URL chưa được nhập key
 */
function localCacheFallbackCall($endpoint, $method, $data) {
    global $cacheDir;
    $cleanNode = explode('/', trim($endpoint, '/'))[0];
    $cacheFile = $cacheDir . '/' . $cleanNode . '.json';

    $current = [];
    if (file_exists($cacheFile)) {
        $current = json_decode(@file_get_contents($cacheFile), true) ?: [];
    }

    // Khởi tạo mặc định nếu rỗng
    if (empty($current)) {
        $now = round(microtime(true) * 1000);
        if ($cleanNode === 'users') {
            $adminId = 'usr_admin';
            $current[$adminId] = [
                'id' => $adminId,
                'username' => DEFAULT_ADMIN_USER,
                'passwordHash' => DEFAULT_ADMIN_HASH,
                'role' => 'admin',
                'status' => 'approved',
                'token' => 'admin_token_' . time(),
                'createdAt' => $now
            ];
        } elseif ($cleanNode === 'channel_info') {
            $current = [
                'name' => 'Kênh Tin Tức Telegram 🚀',
                'avatar' => 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=120&auto=format&fit=crop&q=80',
                'description' => 'Kênh tin nhắn thời gian thực vận hành qua Firebase REST API JSON (cURL PHP).',
                'subscribersCount' => 1248,
                'pinnedMessageId' => 'msg_welcome_01'
            ];
        } elseif ($cleanNode === 'messages') {
            $current = [
                'msg_welcome_01' => [
                    'id' => 'msg_welcome_01',
                    'author' => 'admin',
                    'text' => "🌟 Chào mừng bạn đến với Kênh Tin Nhắn Telegram!\n\n- Giao diện Telegram Dark Mode (#0e1621) chuẩn mực.\n- Kết nối trực tiếp với Firebase Realtime Database qua REST API JSON (.json).\n- Tin nhắn mới nhất nằm TRÊN CÙNG (Reverse order).\n- Rate Limiting 2s chống spam.\n- Mật khẩu mã hóa SHA-256 an toàn.",
                    'timestamp' => $now - 3600000,
                    'isPinned' => true,
                    'isEdited' => false,
                    'views' => 640
                ]
            ];
        }
        @file_put_contents($cacheFile, json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    }

    $parts = explode('/', trim($endpoint, '/'));
    $subKey = isset($parts[1]) ? $parts[1] : null;

    if ($method === 'GET') {
        if ($subKey) {
            return ['success' => true, 'data' => isset($current[$subKey]) ? $current[$subKey] : null];
        }
        return ['success' => true, 'data' => $current];
    } elseif ($method === 'POST') {
        $genId = '-msg_' . time() . '_' . mt_rand(100, 999);
        if (is_array($data)) $data['id'] = $genId;
        $current[$genId] = $data;
        @file_put_contents($cacheFile, json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        return ['success' => true, 'data' => ['name' => $genId]];
    } elseif ($method === 'PATCH' || $method === 'PUT') {
        if ($subKey) {
            $current[$subKey] = array_merge(isset($current[$subKey]) ? $current[$subKey] : [], (array)$data);
        } else {
            $current = array_merge($current, (array)$data);
        }
        @file_put_contents($cacheFile, json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        return ['success' => true, 'data' => $data];
    } elseif ($method === 'DELETE') {
        if ($subKey) {
            unset($current[$subKey]);
        }
        @file_put_contents($cacheFile, json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        return ['success' => true, 'data' => null];
    }

    return ['success' => true, 'data' => $current];
}

// Lấy payload JSON từ POST request
$rawInput = file_get_contents('php://input');
$postData = json_decode($rawInput, true);
if (!is_array($postData)) {
    $postData = $_POST;
}

$action = isset($_GET['action']) ? trim($_GET['action']) : (isset($postData['action']) ? trim($postData['action']) : '');

function sendJsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Xác thực User qua Token gửi từ Header hoặc Body
 */
function authenticateUser($postData) {
    $headers = getallheaders();
    $token = '';
    if (isset($headers['Authorization'])) {
        $token = str_replace('Bearer ', '', $headers['Authorization']);
    } elseif (isset($headers['X-User-Token'])) {
        $token = $headers['X-User-Token'];
    } elseif (isset($postData['token'])) {
        $token = $postData['token'];
    }

    if (!$token) return null;

    $usersRes = firebaseRestCall('users', 'GET');
    $users = is_array($usersRes['data']) ? $usersRes['data'] : [];

    foreach ($users as $id => $u) {
        if (isset($u['token']) && $u['token'] === $token) {
            $u['id'] = $id;
            return $u;
        }
    }
    return null;
}

// ============================================================================
// 2. ROUTING & XỬ LÝ REST API ACTIONS
// ============================================================================

switch ($action) {

    // --- 1. LẤY DỮ LIỆU KÊNH (GET /messages.json & /channel_info.json) ---
    case 'get_data':
        $messagesRes = firebaseRestCall('messages', 'GET');
        $channelRes = firebaseRestCall('channel_info', 'GET');
        $usersRes = firebaseRestCall('users', 'GET');

        $rawMessages = is_array($messagesRes['data']) ? $messagesRes['data'] : [];
        $channel = is_array($channelRes['data']) ? $channelRes['data'] : [];
        $users = is_array($usersRes['data']) ? $usersRes['data'] : [];

        // Đảm bảo mỗi tin nhắn có id
        $messages = [];
        foreach ($rawMessages as $k => $v) {
            if (is_array($v)) {
                $v['id'] = isset($v['id']) ? $v['id'] : $k;
                $messages[$k] = $v;
            }
        }

        // Sắp xếp tin nhắn MỚI NHẤT TRÊN CÙNG (Reverse order)
        uasort($messages, function($a, $b) {
            $tA = isset($a['timestamp']) ? $a['timestamp'] : 0;
            $tB = isset($b['timestamp']) ? $b['timestamp'] : 0;
            return $tB - $tA;
        });

        $approvedCount = 0;
        foreach ($users as $u) {
            if (isset($u['status']) && $u['status'] === 'approved') {
                $approvedCount++;
            }
        }

        sendJsonResponse([
            'status' => 'success',
            'server' => 'PHP cURL -> Firebase REST API',
            'channel_info' => $channel,
            'messages' => (object)$messages,
            'approved_members' => $approvedCount,
            'server_time' => round(microtime(true) * 1000)
        ]);
        break;

    // --- 2. ĐĂNG NHẬP (LOGIN VỚI MẬT KHẨU SHA-256) ---
    case 'login':
        $username = isset($postData['username']) ? trim($postData['username']) : '';
        $password = isset($postData['password']) ? trim($postData['password']) : '';

        if (!$username || !$password) {
            sendJsonResponse(['status' => 'error', 'message' => 'Vui lòng nhập tên đăng nhập và mật khẩu.'], 400);
        }

        // Hỗ trợ mật khẩu đã hash SHA-256 từ client (Web Crypto API) hoặc hash tại server
        $passwordHash = (strlen($password) === 64 && ctype_xdigit($password)) ? strtolower($password) : hash('sha256', $password);

        // Đọc danh sách users từ Firebase: GET /users.json
        $usersRes = firebaseRestCall('users', 'GET');
        $users = is_array($usersRes['data']) ? $usersRes['data'] : [];

        $foundUser = null;
        $foundUserId = null;

        foreach ($users as $id => $u) {
            if (isset($u['username']) && strcasecmp($u['username'], $username) === 0) {
                $foundUser = $u;
                $foundUserId = $id;
                break;
            }
        }

        // Tự động khởi tạo Admin vào Firebase nếu chưa tồn tại
        if (!$foundUser && strcasecmp($username, DEFAULT_ADMIN_USER) === 0) {
            if ($passwordHash === DEFAULT_ADMIN_HASH) {
                $foundUserId = 'usr_admin';
                $foundUser = [
                    'id' => $foundUserId,
                    'username' => DEFAULT_ADMIN_USER,
                    'passwordHash' => DEFAULT_ADMIN_HASH,
                    'role' => 'admin',
                    'status' => 'approved',
                    'createdAt' => round(microtime(true) * 1000)
                ];
                firebaseRestCall("users/{$foundUserId}", 'PUT', $foundUser);
            }
        }

        if (!$foundUser || $foundUser['passwordHash'] !== $passwordHash) {
            sendJsonResponse(['status' => 'error', 'message' => 'Tên đăng nhập hoặc mật khẩu không chính xác.'], 401);
        }

        // Tạo token phiên và cập nhật vào Firebase qua PATCH /users/{userId}.json
        $token = hash('sha256', $foundUserId . '_' . time() . '_' . mt_rand(1000, 9999));
        firebaseRestCall("users/{$foundUserId}", 'PATCH', ['token' => $token]);

        sendJsonResponse([
            'status' => 'success',
            'message' => 'Đăng nhập thành công!',
            'token' => $token,
            'user' => [
                'id' => $foundUserId,
                'username' => $foundUser['username'],
                'role' => $foundUser['role'],
                'status' => $foundUser['status']
            ]
        ]);
        break;

    // --- 3. ĐĂNG KÝ (REGISTER) - MẶC ĐỊNH LÀ PENDING ---
    case 'register':
        $username = isset($postData['username']) ? trim($postData['username']) : '';
        $password = isset($postData['password']) ? trim($postData['password']) : '';

        if (strlen($username) < 3) {
            sendJsonResponse(['status' => 'error', 'message' => 'Tên đăng nhập phải có ít nhất 3 ký tự.'], 400);
        }
        if (strlen($password) < 4) {
            sendJsonResponse(['status' => 'error', 'message' => 'Mật khẩu phải có ít nhất 4 ký tự.'], 400);
        }

        $usersRes = firebaseRestCall('users', 'GET');
        $users = is_array($usersRes['data']) ? $usersRes['data'] : [];

        foreach ($users as $u) {
            if (isset($u['username']) && strcasecmp($u['username'], $username) === 0) {
                sendJsonResponse(['status' => 'error', 'message' => 'Tên đăng nhập này đã được sử dụng.'], 409);
            }
        }

        $newId = 'usr_' . time() . '_' . mt_rand(100, 999);
        // Hỗ trợ mật khẩu đã hash SHA-256 từ client hoặc hash tại server
        $passwordHash = (strlen($password) === 64 && ctype_xdigit($password)) ? strtolower($password) : hash('sha256', $password);
        $token = hash('sha256', $newId . '_' . time());

        $newUser = [
            'id' => $newId,
            'username' => htmlspecialchars($username, ENT_QUOTES, 'UTF-8'),
            'passwordHash' => $passwordHash,
            'role' => 'user',
            'status' => 'pending', // Luôn ở trạng thái Chờ duyệt
            'token' => $token,
            'createdAt' => round(microtime(true) * 1000)
        ];

        // Ghi vào Firebase: PUT /users/{newId}.json
        firebaseRestCall("users/{$newId}", 'PUT', $newUser);

        sendJsonResponse([
            'status' => 'success',
            'message' => 'Đăng ký thành công! Tài khoản đang ở trạng thái Chờ duyệt (Pending) bởi Admin.',
            'token' => $token,
            'user' => [
                'id' => $newId,
                'username' => $newUser['username'],
                'role' => 'user',
                'status' => 'pending'
            ]
        ]);
        break;

    // --- 4. GỬI TIN NHẮN (POST /messages.json) - RATE LIMITING 2 GIÂY ---
    case 'post_message':
    case 'send_message':
        $user = authenticateUser($postData);
        if (!$user) {
            sendJsonResponse(['status' => 'error', 'message' => 'Yêu cầu đăng nhập để gửi tin nhắn.'], 401);
        }

        if ($user['role'] !== 'admin' && $user['status'] !== 'approved') {
            sendJsonResponse(['status' => 'error', 'message' => 'Tài khoản của bạn chưa được phê duyệt để gửi tin.'], 403);
        }

        // Chống Spam: Rate Limiting 2 giây
        $now = round(microtime(true) * 1000);
        if (isset($user['lastSent'])) {
            $diff = $now - $user['lastSent'];
            if ($diff < 2000) {
                sendJsonResponse(['status' => 'error', 'message' => 'Rate limit: Vui lòng chờ 2 giây giữa mỗi lần gửi tin!'], 429);
            }
        }

        $text = isset($postData['text']) ? trim($postData['text']) : '';
        if (!$text) {
            sendJsonResponse(['status' => 'error', 'message' => 'Nội dung tin nhắn không được để trống.'], 400);
        }

        // Chống XSS an toàn
        $safeText = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $isPinned = (!empty($postData['isPinned']) && $user['role'] === 'admin');

        $msgData = [
            'author' => $user['username'],
            'text' => $safeText,
            'timestamp' => $now,
            'isEdited' => false,
            'isPinned' => $isPinned,
            'views' => 1
        ];

        // POST request tới Firebase: POST /messages.json
        $postRes = firebaseRestCall('messages', 'POST', $msgData);
        $newKey = isset($postRes['data']['name']) ? $postRes['data']['name'] : 'msg_' . time();
        $msgData['id'] = $newKey;

        // Cập nhật lại id trong node vừa tạo: PATCH /messages/{id}.json
        firebaseRestCall("messages/{$newKey}", 'PATCH', ['id' => $newKey]);

        // Nếu admin ghim tin nhắn, cập nhật channel_info
        if ($isPinned) {
            firebaseRestCall('channel_info', 'PATCH', ['pinnedMessageId' => $newKey]);
        }

        // Cập nhật mốc lastSent của user: PATCH /users/{userId}.json
        firebaseRestCall("users/{$user['id']}", 'PATCH', ['lastSent' => $now]);

        sendJsonResponse([
            'status' => 'success',
            'message' => 'Tin nhắn đã được đăng thành công!',
            'data' => $msgData
        ]);
        break;

    // --- 5. CHỈNH SỬA TIN NHẮN (PATCH /messages/{id}.json) ---
    case 'edit_message':
        $user = authenticateUser($postData);
        if (!$user) {
            sendJsonResponse(['status' => 'error', 'message' => 'Yêu cầu đăng nhập.'], 401);
        }

        $msgId = isset($postData['id']) ? trim($postData['id']) : '';
        $text = isset($postData['text']) ? trim($postData['text']) : '';

        if (!$msgId || !$text) {
            sendJsonResponse(['status' => 'error', 'message' => 'Thiếu ID hoặc nội dung tin nhắn.'], 400);
        }

        // Lấy tin nhắn từ Firebase: GET /messages/{id}.json
        $msgRes = firebaseRestCall("messages/{$msgId}", 'GET');
        $msg = $msgRes['data'];

        if (!$msg) {
            sendJsonResponse(['status' => 'error', 'message' => 'Không tìm thấy tin nhắn cần sửa.'], 404);
        }

        if ($user['role'] !== 'admin' && $msg['author'] !== $user['username']) {
            sendJsonResponse(['status' => 'error', 'message' => 'Bạn không có quyền sửa tin nhắn này.'], 403);
        }

        $safeText = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $patchData = [
            'text' => $safeText,
            'isEdited' => true,
            'editedAt' => round(microtime(true) * 1000)
        ];

        // PATCH request tới Firebase: PATCH /messages/{id}.json
        firebaseRestCall("messages/{$msgId}", 'PATCH', $patchData);

        sendJsonResponse(['status' => 'success', 'message' => 'Đã cập nhật tin nhắn!']);
        break;

    // --- 6. XÓA TIN NHẮN (DELETE /messages/{id}.json) ---
    case 'delete_message':
        $user = authenticateUser($postData);
        if (!$user) {
            sendJsonResponse(['status' => 'error', 'message' => 'Yêu cầu đăng nhập.'], 401);
        }

        $msgId = isset($postData['id']) ? trim($postData['id']) : '';
        $msgRes = firebaseRestCall("messages/{$msgId}", 'GET');
        $msg = $msgRes['data'];

        if (!$msg) {
            sendJsonResponse(['status' => 'error', 'message' => 'Không tìm thấy tin nhắn.'], 404);
        }

        if ($user['role'] !== 'admin' && $msg['author'] !== $user['username']) {
            sendJsonResponse(['status' => 'error', 'message' => 'Bạn không có quyền xóa tin nhắn này.'], 403);
        }

        // DELETE request tới Firebase: DELETE /messages/{id}.json
        firebaseRestCall("messages/{$msgId}", 'DELETE');

        // Nếu tin bị xóa là tin đang ghim, gỡ ghim trong channel_info
        $chanRes = firebaseRestCall('channel_info', 'GET');
        if (isset($chanRes['data']['pinnedMessageId']) && $chanRes['data']['pinnedMessageId'] === $msgId) {
            firebaseRestCall('channel_info', 'PATCH', ['pinnedMessageId' => null]);
        }

        sendJsonResponse(['status' => 'success', 'message' => 'Đã xóa tin nhắn.']);
        break;

    // --- 7. GHIM / BỎ GHIM TIN NHẮN (PATCH /messages/{id}.json & /channel_info.json) ---
    case 'pin_message':
        $user = authenticateUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendJsonResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền ghim tin nhắn.'], 403);
        }

        $msgId = isset($postData['id']) ? trim($postData['id']) : '';
        $isPinned = !empty($postData['isPinned']);

        if ($isPinned) {
            // Cập nhật tin nhắn và channel_info
            firebaseRestCall("messages/{$msgId}", 'PATCH', ['isPinned' => true]);
            firebaseRestCall('channel_info', 'PATCH', ['pinnedMessageId' => $msgId]);
        } else {
            firebaseRestCall("messages/{$msgId}", 'PATCH', ['isPinned' => false]);
            firebaseRestCall('channel_info', 'PATCH', ['pinnedMessageId' => null]);
        }

        sendJsonResponse(['status' => 'success', 'message' => $isPinned ? 'Đã ghim tin nhắn!' : 'Đã bỏ ghim tin nhắn.']);
        break;

    // --- 8. TĂNG LƯỢT XEM (PATCH /messages/{id}.json) ---
    case 'increment_views':
        $msgId = isset($postData['id']) ? trim($postData['id']) : '';
        if ($msgId) {
            $msgRes = firebaseRestCall("messages/{$msgId}", 'GET');
            if ($msgRes['data']) {
                $views = (isset($msgRes['data']['views']) ? $msgRes['data']['views'] : 0) + 1;
                firebaseRestCall("messages/{$msgId}", 'PATCH', ['views' => $views]);
                sendJsonResponse(['status' => 'success', 'views' => $views]);
            }
        }
        sendJsonResponse(['status' => 'error', 'message' => 'Không hợp lệ.'], 400);
        break;

    // --- 9. QUẢN LÝ THÀNH VIÊN (ADMIN ONLY) ---
    case 'get_users':
        $user = authenticateUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendJsonResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền xem danh sách thành viên.'], 403);
        }

        $usersRes = firebaseRestCall('users', 'GET');
        $users = is_array($usersRes['data']) ? $usersRes['data'] : [];
        $sanitizedList = [];

        foreach ($users as $id => $u) {
            $sanitizedList[] = [
                'id' => isset($u['id']) ? $u['id'] : $id,
                'username' => isset($u['username']) ? $u['username'] : '',
                'role' => isset($u['role']) ? $u['role'] : 'user',
                'status' => isset($u['status']) ? $u['status'] : 'pending',
                'createdAt' => isset($u['createdAt']) ? $u['createdAt'] : null
            ];
        }
        sendJsonResponse(['status' => 'success', 'users' => $sanitizedList]);
        break;

    case 'approve_user':
        $user = authenticateUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendJsonResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền duyệt thành viên.'], 403);
        }

        $targetId = isset($postData['id']) ? trim($postData['id']) : '';
        firebaseRestCall("users/{$targetId}", 'PATCH', ['status' => 'approved']);
        sendJsonResponse(['status' => 'success', 'message' => 'Đã duyệt tài khoản thành công!']);
        break;

    case 'reject_user':
        $user = authenticateUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendJsonResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền từ chối.'], 403);
        }

        $targetId = isset($postData['id']) ? trim($postData['id']) : '';
        firebaseRestCall("users/{$targetId}", 'DELETE');
        sendJsonResponse(['status' => 'success', 'message' => 'Đã từ chối và xóa tài khoản.']);
        break;

    case 'toggle_role':
        $user = authenticateUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendJsonResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền thay đổi vai trò.'], 403);
        }

        $targetId = isset($postData['id']) ? trim($postData['id']) : '';
        $targetRes = firebaseRestCall("users/{$targetId}", 'GET');
        if ($targetRes['data']) {
            $newRole = (isset($targetRes['data']['role']) && $targetRes['data']['role'] === 'admin') ? 'user' : 'admin';
            firebaseRestCall("users/{$targetId}", 'PATCH', ['role' => $newRole]);
            sendJsonResponse(['status' => 'success', 'message' => "Đã đổi vai trò thành {$newRole}!"]);
        }
        sendJsonResponse(['status' => 'error', 'message' => 'Không tìm thấy người dùng.'], 404);
        break;

    case 'update_channel':
        $user = authenticateUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendJsonResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền cập nhật cài đặt kênh.'], 403);
        }

        $patch = [];
        if (isset($postData['name']) && trim($postData['name'])) {
            $patch['name'] = htmlspecialchars(trim($postData['name']), ENT_QUOTES, 'UTF-8');
        }
        if (isset($postData['avatar']) && trim($postData['avatar'])) {
            $patch['avatar'] = trim($postData['avatar']);
        }
        if (isset($postData['description'])) {
            $patch['description'] = htmlspecialchars(trim($postData['description']), ENT_QUOTES, 'UTF-8');
        }

        firebaseRestCall('channel_info', 'PATCH', $patch);
        sendJsonResponse(['status' => 'success', 'message' => 'Đã lưu cài đặt kênh!']);
        break;

    default:
        sendJsonResponse(['status' => 'error', 'message' => 'Hành động không xác định (Unknown action).'], 400);
        break;
}
