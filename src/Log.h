#ifndef LOG_H
#define LOG_H

#include <string>
#include <ctime>

namespace Log
{

/*
*@brief 日志颜色枚举
*@note  取值为 ANSI SGR 前景色转义码(如 Red=31)，由 set_color 输出为
*       "\033[<code>m" 来控制控制台颜色
*/
enum struct Color
{
    Black = 30,
    Blue = 34,
    Green = 32,
    Cyan = 36,
    Red = 31,
    Magenta = 35,
    Brown = 33,
    LightGray = 37,
    DarkGray = 90,
    LightBlue = 94,
    LightGreen = 92,
    LightCyan = 96,
    LightRed = 91,
    LightMagenta = 95,
    Yellow = 93,
    White = 97
};

/*
 *@struct Log_msg
 *@brief 日志消息结构体
 */
struct Log_msg
{
    time_t timestamp;
    Color color;
    std::string title;
    std::string log;
    bool access_log = false; // true: 属于访问日志，写入独立文件
};

/*
*@brief 设置日志输出颜色(输出 ANSI 转义序列)
*@param item 颜色枚举值(ANSI SGR 前景色码)
  *@note  直接向标准输出写入 ANSI SGR 转义序列，不依赖平台专有 API；
*       终端需支持 ANSI 转义序列才能看到颜色
*/
void set_color(Color item);

/*
 *@brief 启用/禁用彩色输出
 *@param enable true: 输出 ANSI 颜色(默认)；false: 只输出纯文本，不写任何转义序列
 *@note  仅影响控制台输出，落盘文件日志本来就不含转义序列；
 *       由配置项 base_msg.colorful_log 控制，供不支持 ANSI 的终端/平台关闭着色。
 *       关闭后 set_color 不再输出任何内容。
 */
void set_colorful(bool enable);

/*
 *@brief 查询当前是否启用彩色输出
 *@return true 表示会输出 ANSI 颜色
 */
bool colorful() noexcept;


/*
 *@brief 输出错误日志
 *@param msg 错误信息
 *@note  形参按值接收:调用方传临时字符串(绝大多数情况)时可以直接移动进
 *       日志队列,省掉一次整串拷贝
 */
void error(std::string msg);
/*
 *@brief 输出警告日志
 *@param msg 警告信息
 */
void warning(std::string msg);
/*
 *@brief 输出普通日志
 *@param msg 日志信息
 *@param item 日志颜色枚举值，默认为浅灰色
 *@param title 日志标题，默认为"LOG"
 */
void log(std::string msg,
         Color item = Color::LightGray,
         const std::string &title = "LOG");
/*
 *@brief 输出访问日志(连接/请求/响应/WebSocket)
 *@param msg 日志信息
 *@param item 日志颜色枚举值，默认为浅灰色
 *@param title 日志标题，默认为"ACCESS"
 *@note  访问日志除输出到控制台外，单独落盘到 LOG/access.<日期>.txt，
 *       与框架主日志(LOG/<日期>.txt)分开，便于过滤与分析
 */
void access(std::string msg,
            Color item = Color::LightGray,
            const std::string &title = "ACCESS");
/*
 *@brief 输出调试日志
 *@param msg 调试信息
 */
void debug(std::string msg);

/*
 *@brief 获取当前时间的字符串表示
 *@param now 当前时间，默认为当前系统时间
 *@return 时间字符串，格式为"YYYY-MM-DD HH:MM:SS"
 */
std::string get_tim(time_t now = std::time(0));
/*
 *@brief 获取当前日期的字符串表示
 *@param day 偏移天数，默认为0表示今天，1表示明天，-1表示昨天
 *@return 日期字符串，格式为"YYYY-MM-DD"
 */
std::string get_date(int day = 0);

/*
 *@brief 把外部可控文本压成单行,避免日志注入
 *@param text 原始文本
 *@return 去掉 '\r'、'\n' 换成空格、其它控制字符换成 '?' 的文本
 *@note  请求行 / URL / Host / WebSocket 关闭原因等字段来自网络,直接拼接进
 *       日志会让对端用换行伪造出额外的日志行(日志注入)。凡是"外部输入直接进
 *       日志"的位置都要先过一遍本函数。
 *       控制台与文件日志的内容格式不因此改变(正常文本原样返回)。
 */
std::string sanitize(const std::string &text);

/*
 *@brief 把外部可控文本清洗后追加到日志文本
 *@param out 目标字符串
 *@param text 原始文本
 *@note  结果与 `out += sanitize(text)` 完全一致,区别是"本来就不需要清洗"的
 *       常见情况直接追加,不做任何额外分配 —— 这条路径在每个请求的访问日志里
 *       要走好几次,所以单独提供一个零拷贝版本。
 */
void append_sanitized(std::string &out, const std::string &text);

/*
 *@brief 开始日志输出
 */
void start_output();
/*
 *@brief 停止日志输出
 */
void stop_output();

} // namespace Log

#endif // LOG_H
