# Xray

本仓库是 [Xray-core](https://github.com/XTLS/Xray-core) 的下游衍生仓库，主要用于自动化同步上游代码并维护自定义修改。

This repository is a downstream fork of [Xray-core](https://github.com/XTLS/Xray-core), used to automatically synchronize upstream source code and maintain custom modifications.

---

## 仓库结构与分支说明
## Repository Structure & Branch Policy

- **main 分支**：每天自动拉取 Xray-core 上游仓库的最新源码。 \
  **main branch**: Automatically pulls source code from the upstream repository daily.

- **master 分支**：本分支不包含任何代码，请勿向此分支提交合并请求。 \
  **master branch**: Contains no code. Please do not submit Pull Requests to this branch.

- **版本分支与标签**：带有版本号的仓库/分支对应 Xray 对应版本的代码以及本仓库的定制修改。 \
  **Versioned branches & tags**: Version-tagged branches/repositories correspond to specific Xray release versions combined with custom modifications of this repository.

---

## 贡献指南
## Contribution Guidelines

本仓库仅接受 Bug 修复类代码贡献。如果您希望增加新功能，请将代码提交至上游仓库。
This repository only accepts contributions for bug fixes. If you wish to add new features, please submit your Pull Requests directly to the upstream repository.

提交贡献时请勿发送 PR 到 `master` 分支，请提交至对应的功能或修复分支。
Please do not submit PRs to the `master` branch. Kindly open Pull Requests against other relevant target branches.

---

## 致谢与贡献者
## Acknowledgments & Credits

本项目的存在离不开发育完善的开源社区，在此向以下项目及其贡献者表达诚挚感谢： \
This project exists thanks to the vibrant open-source community. Sincere gratitude is extended to the following upstream projects and their contributors:

### Xray-core
- 项目地址：[XTLS/Xray-core](https://github.com/XTLS/Xray-core) \
  Repository: [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- 感谢 [RPRX](https://github.com/RPRX)、[Fangliding](https://github.com/Fangliding)、[yuhan6665](https://github.com/yuhan6665)、[LjhAUMEM](https://github.com/LjhAUMEM) 以及所有为 Xray-core 作出贡献的开发者。 \
  Special thanks to [RPRX](https://github.com/RPRX), [Fangliding](https://github.com/Fangliding), [yuhan6665](https://github.com/yuhan6665), [LjhAUMEM](https://github.com/LjhAUMEM), and all other contributors to Xray-core.

### v2rayN&G
- 项目地址：[2dust/v2rayN](https://github.com/2dust/v2rayN) [2dust/v2rayNG](https://github.com/2dust/v2rayNG) \
  Repository: [2dust/v2rayN](https://github.com/2dust/v2rayN) [2dust/v2rayNG](https://github.com/2dust/v2rayNG)
- 感谢 [2dust](https://github.com/2dust)、[DHR60](https://github.com/DHR60)、[drownrat](https://github.com/drownrat) 以及 v2rayN 项目的所有贡献者。 \
  Special thanks to [2dust](https://github.com/2dust), [DHR60](https://github.com/DHR60), [drownrat](https://github.com/drownrat), and all other contributors to the v2rayN project.
