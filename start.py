"""Find one IPA beside this file and build a new unsigned IPA in output/."""
from datetime import datetime
from pathlib import Path
import subprocess
import sys


def main(folder=None):
    if sys.version_info < (3, 11):
        print('需要 Python 3.11 或更高版本。', flush=True)
        return 2
    folder = Path(folder).resolve() if folder is not None else Path(__file__).resolve().parent
    inputs = sorted(p for p in folder.iterdir() if p.is_file() and p.suffix.lower() == '.ipa')
    if not inputs:
        print('已停止：请把指定的 2.7.81 砸壳原包放在本工具根目录，然后重新双击开始修补.bat。', flush=True)
        return 2
    if len(inputs) != 1:
        print('已停止：根目录有多个 IPA，无法确定原包。请只保留一个待修补的原包：', flush=True)
        for item in inputs:
            print('  ' + item.name, flush=True)
        return 2
    if not (folder / 'kit/payload.zip').is_file():
        print('已停止：缺少 kit/payload.zip。源码包不含 SDK 组件，请使用完整本地工具及匹配且有权使用的组件。', flush=True)
        return 2
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    output = folder / 'output' / ('Arknights-2.7.81-v7.5-' + stamp + '-unsigned.ipa')
    print('原包：' + str(inputs[0]), flush=True)
    print('输出：' + str(output), flush=True)
    print('开始校验及修补，请保持窗口打开；大文件处理可能需要几分钟。', flush=True)
    try:
        result = subprocess.run([
            sys.executable, '-X', 'utf8', str(folder / 'arkpatch_decrypted.py'),
            'patch', str(inputs[0]), '--output', str(output),
        ], cwd=str(folder))
    except OSError as exc:
        print('启动失败：' + str(exc), flush=True)
        return 2
    if result.returncode == 0:
        print('\n修补完成：' + str(output), flush=True)
        print('同目录附有校验报告。请使用 iLoader 签名安装生成的 IPA。', flush=True)
    else:
        print('\n修补失败，请查看上方 STOP 原因。不会覆盖原包；不要使用未完成的文件。', flush=True)
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
