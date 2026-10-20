<?php
/**
 * ============================================================================
 * TELEGRAM CHANNEL BACKEND API (PHP + JSON Storage / MySQL Ready)
 * ============================================================================
 * Tự động tạo thư mục /data và các file JSON nếu chưa tồn tại.
 * Mật khẩu được mã hóa an toàn bằng SHA-256.
 * Chống XSS, Rate Limiting (2 giây), phân quyền Admin / Member / Pending.
 * ============================================================================
 */

// Bật hiển thị lỗi khi debug (tắt trên production nếu cần)
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

// Đường dẫn lưu trữ dữ liệu JSON
$dataDir = __DIR__ . '/data';
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0755, true);
    // Bảo vệ thư mục data khỏi truy cập trực tiếp từ trình duyệt
    file_put_contents($dataDir . '/.htaccess', "Deny from all\n");
}

$usersFile = $dataDir . '/users.json';
$messagesFile = $dataDir . '/messages.json';
$channelFile = $dataDir . '/channel.json';

// Mật khẩu và tài khoản Admin mặc định
define('DEFAULT_ADMIN_USER', 'admin');
define('DEFAULT_ADMIN_PASS', '0386744127');
// SHA-256 của "0386744127"
define('DEFAULT_ADMIN_HASH', '267cae80ce3fea93e60a755bf0ee2f7f7f2a1c2198a48c93a0730dff6b575a77');

/**
 * Đọc file JSON an toàn với khóa đọc (shared lock)
 */
function readJsonFile($filePath, $default = []) {
    if (!file_exists($filePath)) {
        return $default;
    }
    $fp = fopen($filePath, 'r');
    if (!$fp) return $default;
    flock($fp, LOCK_SH);
    $content = '';
    while (!feof($fp)) {
        $content .= fread($fp, 8192);
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    $data = json_decode($content, true);
    return is_array($data) ? $data : $default;
}

/**
 * Ghi file JSON an toàn với khóa độc quyền (exclusive lock)
 */
function writeJsonFile($filePath, $data) {
    $fp = fopen($filePath, 'c+');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return true;
}

/**
 * Khởi tạo dữ liệu ban đầu nếu chưa có
 */
function initDefaultData() {
    global $usersFile, $messagesFile, $channelFile;

    // 1. Khởi tạo Users
    $users = readJsonFile($usersFile, []);
    $adminExists = false;
    foreach ($users as $u) {
        if ($u['username'] === DEFAULT_ADMIN_USER) {
            $adminExists = true;
            break;
        }
    }
    if (!$adminExists) {
        $adminId = 'usr_admin_' . time();
        $users[$adminId] = [
            'id' => $adminId,
            'username' => DEFAULT_ADMIN_USER,
            'passwordHash' => DEFAULT_ADMIN_HASH,
            'role' => 'admin',
            'status' => 'approved',
            'token' => hash('sha256', $adminId . '_token_' . time()),
            'createdAt' => time() * 1000
        ];
        writeJsonFile($usersFile, $users);
    }

    // 2. Khởi tạo Channel Info
    $channel = readJsonFile($channelFile, null);
    if (!$channel) {
        $channel = [
            'name' => 'Kênh Tin Tức Telegram (PHP Backend) 🚀',
            'avatar' => 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=120&auto=format&fit=crop&q=80',
            'description' => 'Kênh tin nhắn thời gian thực vận hành trên Máy chủ PHP + HTML thuần. Hỗ trợ đầy đủ phân quyền & chống spam.',
            'subscribersCount' => 1248,
            'pinnedMessageId' => 'msg_welcome_01'
        ];
        writeJsonFile($channelFile, $channel);
    }

    // 3. Khởi tạo Messages
    $messages = readJsonFile($messagesFile, null);
    if (!$messages || empty($messages)) {
        $now = round(microtime(true) * 1000);
        $messages = [
            'msg_welcome_01' => [
                'id' => 'msg_welcome_01',
                'author' => 'admin',
                'text' => "🌟 Chào mừng bạn đến với Kênh Tin Nhắn Telegram (Vận hành bởi PHP Backend)!\n\n- Tin nhắn mới nhất hiển thị TRÊN CÙNG (Reverse order).\n- Mật khẩu mã hóa SHA-256 an toàn.\n- Rate limiting chống spam 2 giây.\n- Tích hợp duyệt thành viên (Pending -> Approved).",
                'timestamp' => $now - 3600000,
                'isPinned' => true,
                'isEdited' => false,
                'views' => 642
            ],
            'msg_welcome_02' => [
                'id' => 'msg_welcome_02',
                'author' => 'admin',
                'text' => "⚡ Hệ thống đang kết nối trực tiếp với file api.php. Mọi thao tác Thêm, Sửa, Xóa, Ghim và Duyệt thành viên được xử lý ngay lập tức trên máy chủ PHP.",
                'timestamp' => $now - 1200000,
                'isPinned' => false,
                'isEdited' => false,
                'views' => 380
            ]
        ];
        writeJsonFile($messagesFile, $messages);
    }
}

initDefaultData();

// Lấy payload JSON từ POST
$rawInput = file_get_contents('php://input');
$postData = json_decode($rawInput, true);
if (!is_array($postData)) {
    $postData = $_POST;
}

$action = isset($_GET['action']) ? trim($_GET['action']) : (isset($postData['action']) ? trim($postData['action']) : '');

/**
 * Trả về phản hồi JSON
 */
function sendResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Xác thực User qua Token gửi từ Header hoặc Body
 */
function getAuthenticatedUser($postData) {
    global $usersFile;
    $headers = getallheaders();
    $token = '';
    if (isset($headers['Authorization'])) {
        $token = str_replace('Bearer ', '', $headers['Authorization']);
    } elseif (isset($headers['X-User-Token'])) {
        $token = $headers['X-User-Token'];
    } elseif (isset($postData['token'])) {
        $token = $postData['token'];
    } elseif (isset($_GET['token'])) {
        $token = $_GET['token'];
    }

    if (!$token) return null;

    $users = readJsonFile($usersFile, []);
    foreach ($users as $u) {
        if (isset($u['token']) && $u['token'] === $token) {
            return $u;
        }
    }
    return null;
}

// ============================================================================
// ROUTING & XỬ LÝ ACTIONS
// ============================================================================

switch ($action) {

    // --- 1. LẤY DỮ LIỆU KÊNH & TIN NHẮN (GET DATA) ---
    case 'get_data':
        $messages = readJsonFile($messagesFile, []);
        $channel = readJsonFile($channelFile, []);
        $users = readJsonFile($usersFile, []);

        // Sắp xếp tin nhắn MỚI NHẤT TRÊN CÙNG (Reverse order)
        uasort($messages, function($a, $b) {
            return $b['timestamp'] - $a['timestamp'];
        });

        // Đếm số người dùng đã duyệt
        $approvedCount = 0;
        foreach ($users as $u) {
            if (isset($u['status']) && $u['status'] === 'approved') {
                $approvedCount++;
            }
        }

        sendResponse([
            'status' => 'success',
            'server' => 'PHP ' . phpversion(),
            'channel_info' => $channel,
            'messages' => (object)$messages,
            'approved_members' => $approvedCount,
            'server_time' => round(microtime(true) * 1000)
        ]);
        break;

    // --- 2. ĐĂNG NHẬP (LOGIN) ---
    case 'login':
        $username = isset($postData['username']) ? trim($postData['username']) : '';
        $password = isset($postData['password']) ? trim($postData['password']) : '';

        if (!$username || !$password) {
            sendResponse(['status' => 'error', 'message' => 'Vui lòng nhập tên đăng nhập và mật khẩu.'], 400);
        }

        // Mã hóa SHA-256 mật khẩu
        $passwordHash = hash('sha256', $password);

        $users = readJsonFile($usersFile, []);
        $foundUser = null;
        $foundUserId = null;

        foreach ($users as $id => $u) {
            if (strcasecmp($u['username'], $username) === 0) {
                $foundUser = $u;
                $foundUserId = $id;
                break;
            }
        }

        if (!$foundUser || $foundUser['passwordHash'] !== $passwordHash) {
            sendResponse(['status' => 'error', 'message' => 'Tên đăng nhập hoặc mật khẩu không chính xác.'], 401);
        }

        // Tạo token phiên đăng nhập
        $newToken = hash('sha256', $foundUserId . '_' . time() . '_' . mt_rand(1000, 9999));
        $users[$foundUserId]['token'] = $newToken;
        writeJsonFile($usersFile, $users);

        sendResponse([
            'status' => 'success',
            'message' => 'Đăng nhập thành công!',
            'token' => $newToken,
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
            sendResponse(['status' => 'error', 'message' => 'Tên đăng nhập phải có ít nhất 3 ký tự.'], 400);
        }
        if (strlen($password) < 4) {
            sendResponse(['status' => 'error', 'message' => 'Mật khẩu phải có ít nhất 4 ký tự.'], 400);
        }

        $users = readJsonFile($usersFile, []);
        foreach ($users as $u) {
            if (strcasecmp($u['username'], $username) === 0) {
                sendResponse(['status' => 'error', 'message' => 'Tên đăng nhập này đã được sử dụng.'], 409);
            }
        }

        $newId = 'usr_' . time() . '_' . mt_rand(100, 999);
        $passwordHash = hash('sha256', $password);
        $newToken = hash('sha256', $newId . '_' . time() . '_' . mt_rand(1000, 9999));

        $newUser = [
            'id' => $newId,
            'username' => htmlspecialchars($username),
            'passwordHash' => $passwordHash,
            'role' => 'user',
            'status' => 'pending', // Luôn ở trạng thái Chờ duyệt
            'token' => $newToken,
            'createdAt' => round(microtime(true) * 1000)
        ];

        $users[$newId] = $newUser;
        writeJsonFile($usersFile, $users);

        sendResponse([
            'status' => 'success',
            'message' => 'Đăng ký thành công! Tài khoản đang ở trạng thái Chờ duyệt (Pending) bởi Admin.',
            'token' => $newToken,
            'user' => [
                'id' => $newId,
                'username' => $newUser['username'],
                'role' => 'user',
                'status' => 'pending'
            ]
        ]);
        break;

    // --- 4. GỬI TIN NHẮN (SEND MESSAGE) - RATE LIMITING 2 GIÂY ---
    case 'send_message':
        $user = getAuthenticatedUser($postData);
        if (!$user) {
            sendResponse(['status' => 'error', 'message' => 'Yêu cầu đăng nhập để gửi tin nhắn.'], 401);
        }

        if ($user['role'] !== 'admin' && $user['status'] !== 'approved') {
            sendResponse(['status' => 'error', 'message' => 'Tài khoản của bạn chưa được duyệt quyền đăng bài.'], 403);
        }

        // Chống spam: Rate limiting 2 giây (kiểm tra session / user lastSent)
        $now = round(microtime(true) * 1000);
        $users = readJsonFile($usersFile, []);
        if (isset($users[$user['id']]['lastSent'])) {
            $diff = $now - $users[$user['id']]['lastSent'];
            if ($diff < 2000) {
                sendResponse(['status' => 'error', 'message' => 'Rate limit: Vui lòng chờ 2 giây giữa mỗi lần gửi tin!'], 429);
            }
        }

        $text = isset($postData['text']) ? trim($postData['text']) : '';
        if (!$text) {
            sendResponse(['status' => 'error', 'message' => 'Nội dung tin nhắn không được để trống.'], 400);
        }

        // Chống XSS an toàn
        $safeText = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $isPinned = (!empty($postData['isPinned']) && $user['role'] === 'admin');
        $msgId = 'msg_' . time() . '_' . mt_rand(100, 999);

        $newMsg = [
            'id' => $msgId,
            'author' => $user['username'],
            'text' => $safeText,
            'timestamp' => $now,
            'isEdited' => false,
            'isPinned' => $isPinned,
            'views' => 1
        ];

        $messages = readJsonFile($messagesFile, []);
        $messages[$msgId] = $newMsg;

        // Nếu admin ghim tin nhắn, cập nhật channel info
        if ($isPinned) {
            $channel = readJsonFile($channelFile, []);
            // Bỏ ghim các tin trước đó
            foreach ($messages as &$m) {
                if ($m['id'] !== $msgId && !empty($m['isPinned'])) {
                    $m['isPinned'] = false;
                }
            }
            $channel['pinnedMessageId'] = $msgId;
            writeJsonFile($channelFile, $channel);
        }

        writeJsonFile($messagesFile, $messages);

        // Cập nhật lastSent của user
        $users[$user['id']]['lastSent'] = $now;
        writeJsonFile($usersFile, $users);

        sendResponse([
            'status' => 'success',
            'message' => 'Tin nhắn đã được đăng thành công!',
            'data' => $newMsg
        ]);
        break;

    // --- 5. CHỈNH SỬA TIN NHẮN (EDIT MESSAGE) ---
    case 'edit_message':
        $user = getAuthenticatedUser($postData);
        if (!$user) {
            sendResponse(['status' => 'error', 'message' => 'Yêu cầu đăng nhập.'], 401);
        }

        $msgId = isset($postData['id']) ? trim($postData['id']) : '';
        $text = isset($postData['text']) ? trim($postData['text']) : '';

        if (!$msgId || !$text) {
            sendResponse(['status' => 'error', 'message' => 'Thiếu ID hoặc nội dung tin nhắn.'], 400);
        }

        $messages = readJsonFile($messagesFile, []);
        if (!isset($messages[$msgId])) {
            sendResponse(['status' => 'error', 'message' => 'Không tìm thấy tin nhắn cần sửa.'], 404);
        }

        // Quyền: Admin hoặc chính tác giả
        if ($user['role'] !== 'admin' && $messages[$msgId]['author'] !== $user['username']) {
            sendResponse(['status' => 'error', 'message' => 'Bạn không có quyền sửa tin nhắn này.'], 403);
        }

        $messages[$msgId]['text'] = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $messages[$msgId]['isEdited'] = true;
        $messages[$msgId]['editedAt'] = round(microtime(true) * 1000);

        writeJsonFile($messagesFile, $messages);

        sendResponse(['status' => 'success', 'message' => 'Đã cập nhật tin nhắn!', 'data' => $messages[$msgId]]);
        break;

    // --- 6. XÓA TIN NHẮN (DELETE MESSAGE) ---
    case 'delete_message':
        $user = getAuthenticatedUser($postData);
        if (!$user) {
            sendResponse(['status' => 'error', 'message' => 'Yêu cầu đăng nhập.'], 401);
        }

        $msgId = isset($postData['id']) ? trim($postData['id']) : '';
        $messages = readJsonFile($messagesFile, []);
        if (!isset($messages[$msgId])) {
            sendResponse(['status' => 'error', 'message' => 'Không tìm thấy tin nhắn.'], 404);
        }

        if ($user['role'] !== 'admin' && $messages[$msgId]['author'] !== $user['username']) {
            sendResponse(['status' => 'error', 'message' => 'Bạn không có quyền xóa tin nhắn này.'], 403);
        }

        unset($messages[$msgId]);
        writeJsonFile($messagesFile, $messages);

        // Nếu tin bị xóa là tin đang ghim, gỡ ghim
        $channel = readJsonFile($channelFile, []);
        if (isset($channel['pinnedMessageId']) && $channel['pinnedMessageId'] === $msgId) {
            $channel['pinnedMessageId'] = null;
            writeJsonFile($channelFile, $channel);
        }

        sendResponse(['status' => 'success', 'message' => 'Đã xóa tin nhắn.']);
        break;

    // --- 7. GHIM / BỎ GHIM TIN NHẮN (PIN / UNPIN) - ADMIN ONLY ---
    case 'pin_message':
        $user = getAuthenticatedUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền ghim tin nhắn.'], 403);
        }

        $msgId = isset($postData['id']) ? trim($postData['id']) : '';
        $isPinned = !empty($postData['isPinned']);

        $messages = readJsonFile($messagesFile, []);
        $channel = readJsonFile($channelFile, []);

        if ($isPinned) {
            if (!isset($messages[$msgId])) {
                sendResponse(['status' => 'error', 'message' => 'Không tìm thấy tin nhắn.'], 404);
            }
            // Bỏ ghim các tin cũ
            foreach ($messages as &$m) {
                $m['isPinned'] = ($m['id'] === $msgId);
            }
            $channel['pinnedMessageId'] = $msgId;
        } else {
            if (isset($messages[$msgId])) {
                $messages[$msgId]['isPinned'] = false;
            }
            if ($channel['pinnedMessageId'] === $msgId) {
                $channel['pinnedMessageId'] = null;
            }
        }

        writeJsonFile($messagesFile, $messages);
        writeJsonFile($channelFile, $channel);

        sendResponse(['status' => 'success', 'message' => $isPinned ? 'Đã ghim tin nhắn!' : 'Đã bỏ ghim tin nhắn.']);
        break;

    // --- 8. TĂNG LƯỢT XEM (INCREMENT VIEWS) ---
    case 'increment_views':
        $msgId = isset($postData['id']) ? trim($postData['id']) : '';
        if ($msgId) {
            $messages = readJsonFile($messagesFile, []);
            if (isset($messages[$msgId])) {
                $messages[$msgId]['views'] = (isset($messages[$msgId]['views']) ? $messages[$msgId]['views'] : 0) + 1;
                writeJsonFile($messagesFile, $messages);
                sendResponse(['status' => 'success', 'views' => $messages[$msgId]['views']]);
            }
        }
        sendResponse(['status' => 'error', 'message' => 'Không hợp lệ.'], 400);
        break;

    // --- 9. QUẢN LÝ THÀNH VIÊN (ADMIN ONLY) ---
    case 'get_users':
        $user = getAuthenticatedUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền xem danh sách thành viên.'], 403);
        }

        $users = readJsonFile($usersFile, []);
        $sanitizedList = [];
        foreach ($users as $u) {
            $sanitizedList[] = [
                'id' => $u['id'],
                'username' => $u['username'],
                'role' => $u['role'],
                'status' => $u['status'],
                'createdAt' => isset($u['createdAt']) ? $u['createdAt'] : null
            ];
        }
        sendResponse(['status' => 'success', 'users' => $sanitizedList]);
        break;

    case 'approve_user':
        $user = getAuthenticatedUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền duyệt thành viên.'], 403);
        }

        $targetId = isset($postData['id']) ? trim($postData['id']) : '';
        $users = readJsonFile($usersFile, []);
        if (isset($users[$targetId])) {
            $users[$targetId]['status'] = 'approved';
            writeJsonFile($usersFile, $users);
            sendResponse(['status' => 'success', 'message' => "Đã duyệt tài khoản {$users[$targetId]['username']}!"]);
        }
        sendResponse(['status' => 'error', 'message' => 'Không tìm thấy người dùng.'], 404);
        break;

    case 'reject_user':
        $user = getAuthenticatedUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền từ chối.'], 403);
        }

        $targetId = isset($postData['id']) ? trim($postData['id']) : '';
        $users = readJsonFile($usersFile, []);
        if (isset($users[$targetId])) {
            unset($users[$targetId]);
            writeJsonFile($usersFile, $users);
            sendResponse(['status' => 'success', 'message' => 'Đã từ chối và xóa tài khoản.']);
        }
        sendResponse(['status' => 'error', 'message' => 'Không tìm thấy người dùng.'], 404);
        break;

    case 'toggle_role':
        $user = getAuthenticatedUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền thay đổi vai trò.'], 403);
        }

        $targetId = isset($postData['id']) ? trim($postData['id']) : '';
        $users = readJsonFile($usersFile, []);
        if (isset($users[$targetId])) {
            $users[$targetId]['role'] = ($users[$targetId]['role'] === 'admin') ? 'user' : 'admin';
            writeJsonFile($usersFile, $users);
            sendResponse(['status' => 'success', 'message' => "Đã đổi vai trò thành {$users[$targetId]['role']}!"]);
        }
        sendResponse(['status' => 'error', 'message' => 'Không tìm thấy người dùng.'], 404);
        break;

    case 'update_channel':
        $user = getAuthenticatedUser($postData);
        if (!$user || $user['role'] !== 'admin') {
            sendResponse(['status' => 'error', 'message' => 'Chỉ Admin mới có quyền cập nhật cài đặt kênh.'], 403);
        }

        $channel = readJsonFile($channelFile, []);
        if (isset($postData['name']) && trim($postData['name'])) {
            $channel['name'] = htmlspecialchars(trim($postData['name']));
        }
        if (isset($postData['avatar']) && trim($postData['avatar'])) {
            $channel['avatar'] = trim($postData['avatar']);
        }
        if (isset($postData['description'])) {
            $channel['description'] = htmlspecialchars(trim($postData['description']));
        }

        writeJsonFile($channelFile, $channel);
        sendResponse(['status' => 'success', 'message' => 'Đã lưu cài đặt kênh!', 'channel' => $channel]);
        break;

    default:
        sendResponse(['status' => 'error', 'message' => 'Hành động không xác định (Unknown action).'], 400);
        break;
}
