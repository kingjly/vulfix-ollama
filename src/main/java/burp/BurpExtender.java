package burp;  

import java.io.*;  
import java.awt.*;  
import java.awt.event.*;  
import java.io.PrintWriter;  
import java.net.URL; 
import java.net.HttpURLConnection;  
import java.nio.charset.StandardCharsets;  
import java.util.*;  
import java.util.List;  
import java.util.prefs.Preferences;  
import java.util.regex.*;  
import javax.swing.*;  
import org.json.*;  
import java.awt.Color;  
import javax.swing.event.DocumentListener;  
import javax.swing.event.DocumentEvent;
import javax.swing.event.PopupMenuListener;  
import javax.swing.event.PopupMenuEvent; 

public class BurpExtender implements IBurpExtender, ITab {  
    private IBurpExtenderCallbacks callbacks;  
    private IExtensionHelpers helpers;  
    private JPanel mainPanel;  
    private PrintWriter stdout;  
    private JTextArea inputArea;  
    private JTextArea vulnTypeArea;  
    private JTextArea vulnDescArea;  
    private JTextArea vulnFixArea;  
    private JButton analyzeButton;  
    private JButton reAnalyzeButton;  // 新增  
    private DefaultListModel<String> listModel;  
    private JList<String> vulnHistoryList;  
    private Map<String, VulnInfo> vulnInfoMap;  
    private JComboBox<String> modelComboBox;  
    private static final String PREF_MODEL = "selectedModel";  
    private final Preferences prefs = Preferences.userNodeForPackage(BurpExtender.class);  

    private enum AnalysisState {  
        READY,          // 准备分析新漏洞  
        ANALYZING,      // 正在分析中  
        RESULT_SHOWN    // 显示分析结果  
    }  
    
    private AnalysisState currentState = AnalysisState.READY; 

    private void updateUIState(AnalysisState newState) {  
        currentState = newState;  
        String currentInput = inputArea.getText().trim();  
        boolean hasHistory = vulnInfoMap.containsKey(currentInput);  
        
        switch (newState) {  
            case READY:  
                analyzeButton.setText("开始分析");  
                analyzeButton.setEnabled(!currentInput.isEmpty());  
                reAnalyzeButton.setEnabled(hasHistory);  
                inputArea.setEditable(true);  
                vulnHistoryList.setEnabled(true);  
                break;  
                
            case ANALYZING:  
                analyzeButton.setText("分析中...");  
                analyzeButton.setEnabled(false);  
                reAnalyzeButton.setEnabled(false);  
                inputArea.setEditable(false);  
                vulnHistoryList.setEnabled(false);  
                break;  
                
            case RESULT_SHOWN:  
                analyzeButton.setText("开始分析");  
                analyzeButton.setEnabled(false);  
                reAnalyzeButton.setEnabled(true);  
                inputArea.setEditable(true);  
                vulnHistoryList.setEnabled(true);  
                break;  
        }  
    }

    private static class VulnInfo implements Serializable {  
        private static final long serialVersionUID = 1L;  
        String type;  
        String description;  
        String fix;  
        long timestamp;  
    
        VulnInfo(String type, String description, String fix) {  
            this.type = type;  
            this.description = description;  
            this.fix = fix;  
            this.timestamp = System.currentTimeMillis();  
        }  
    }

    private File getDataFile() {  
        String userHome = System.getProperty("user.home");  
        File burpDir = new File(userHome, ".burp");  
        if (!burpDir.exists()) {  
            burpDir.mkdir();  
        }  
        return new File(burpDir, "vulfix_history.dat");  
    }  
    
    private void saveData() {  
        try {  
            File dataFile = getDataFile();  
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(dataFile))) {  
                oos.writeObject(new HashMap<>(vulnInfoMap));  
            }  
        } catch (Exception e) {  
            stdout.println("保存历史记录失败: " + e.getMessage());  
        }  
    }  
    
    private void loadData() {  
        try {  
            File dataFile = getDataFile();  
            if (dataFile.exists()) {  
                try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(dataFile))) {  
                    @SuppressWarnings("unchecked")  
                    HashMap<String, VulnInfo> loadedMap = (HashMap<String, VulnInfo>) ois.readObject();  
                    vulnInfoMap.putAll(loadedMap);  
                    
                    // 更新列表模型  
                    SwingUtilities.invokeLater(() -> {  
                        for (String vulnName : loadedMap.keySet()) {  
                            if (!listModel.contains(vulnName)) {  
                                listModel.addElement(vulnName);  
                            }  
                        }  
                    });  
                }  
            }  
        } catch (Exception e) {  
            stdout.println("加载历史记录失败: " + e.getMessage());  
        }  
    }

    @Override  
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {  
        this.callbacks = callbacks;  
        this.helpers = callbacks.getHelpers();  
        this.stdout = new PrintWriter(callbacks.getStdout(), true);  
        
        SwingUtilities.invokeLater(() -> {  
            try {  
                initializeUI();  
                loadData(); // 加载历史数据  
            } catch (Exception e) {  
                stdout.println("UI初始化失败: " + e.getMessage());  
                e.printStackTrace(stdout);  
            }  
        });  
    }

    private void loadAvailableModels(Runnable onComplete) {  
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {  
            @Override  
            protected Void doInBackground() throws Exception {  
                try {  
                    URL url = new URL("http://127.0.0.1:11434/api/tags");  
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();  
                    conn.setRequestMethod("GET");  
                    conn.setConnectTimeout(5000);  
                    
                    try (BufferedReader reader = new BufferedReader(  
                            new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {  
                        StringBuilder response = new StringBuilder();  
                        String line;  
                        while ((line = reader.readLine()) != null) {  
                            response.append(line);  
                        }  
                        
                        JSONObject json = new JSONObject(response.toString());  
                        JSONArray models = json.getJSONArray("models");  
                        
                        List<String> modelList = new ArrayList<>();  
                        for (int i = 0; i < models.length(); i++) {  
                            JSONObject model = models.getJSONObject(i);  
                            String modelName = model.getString("model");  
                            // 移除了过滤条件，现在会显示所有模型  
                            modelList.add(modelName);  
                        }  
                        
                        // 可选：按字母顺序排序模型列表  
                        Collections.sort(modelList);  
                        
                        SwingUtilities.invokeLater(() -> {  
                            DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>(  
                                modelList.toArray(new String[0]));  
                            modelComboBox.setModel(model);  
                            
                            String savedModel = prefs.get(PREF_MODEL, "");  
                            if (!savedModel.isEmpty() && modelList.contains(savedModel)) {  
                                modelComboBox.setSelectedItem(savedModel);  
                            } else if (model.getSize() > 0) {  
                                modelComboBox.setSelectedIndex(0);  
                                prefs.put(PREF_MODEL, (String) model.getElementAt(0));  
                            }  
                            
                            // 打印加载到的模型数量，用于调试  
                            stdout.println("加载了 " + modelList.size() + " 个模型");  
                            
                            onComplete.run();  
                        });  
                    }  
                } catch (Exception e) {  
                    stdout.println("获取模型列表失败: " + e.getMessage());  
                    SwingUtilities.invokeLater(() -> {  
                        String[] defaultModels = {"qwen2.5:3b", "qwen2.5:7b", "qwen2.5:14b"};  
                        DefaultComboBoxModel<String> model = new DefaultComboBoxModel<>(defaultModels);  
                        modelComboBox.setModel(model);  
                        
                        String savedModel = prefs.get(PREF_MODEL, defaultModels[0]);  
                        modelComboBox.setSelectedItem(savedModel);  
                        
                        onComplete.run();  
                    });  
                }  
                return null;  
            }  
        };  
        worker.execute();  
    }

    private void initializeUI() {  
        mainPanel = new JPanel(new BorderLayout());  
        listModel = new DefaultListModel<>();  
        vulnHistoryList = new JList<>(listModel);  
        vulnInfoMap = new HashMap<>();  
    
        // 左侧历史记录面板  
        JPanel leftPanel = new JPanel(new BorderLayout());  
        leftPanel.setBorder(BorderFactory.createTitledBorder("历史记录"));  
        vulnHistoryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);  
        JScrollPane historyScrollPane = new JScrollPane(vulnHistoryList);  
        historyScrollPane.setPreferredSize(new Dimension(200, 0));  
        leftPanel.add(historyScrollPane, BorderLayout.CENTER);  
    
        // 右侧面板  
        JPanel rightPanel = new JPanel(new BorderLayout(0, 5));  
    
        // 顶部配置和输入面板  
        JPanel topPanel = new JPanel(new GridBagLayout());  
        GridBagConstraints gbc = new GridBagConstraints();  
        gbc.fill = GridBagConstraints.HORIZONTAL;  
        gbc.weightx = 1.0;  
        gbc.insets = new Insets(2, 5, 2, 5);  
    
        // 配置面板  
        JPanel configPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));  
        configPanel.setBorder(BorderFactory.createTitledBorder("配置"));  
        
        String[] modelOptions = {  
            "qwen2.5:3b",
            "qwen2.5:7b",  
            "qwen2.5:14b"  
        };  
        modelComboBox = new JComboBox<>(new String[]{"加载中..."});  
        modelComboBox.addPopupMenuListener(new PopupMenuListener() {  
            private boolean hasLoaded = false;  
            
            @Override  
            public void popupMenuWillBecomeVisible(PopupMenuEvent e) {  
                if (!hasLoaded) {  
                    SwingUtilities.invokeLater(() -> modelComboBox.hidePopup());  
                    
                    loadAvailableModels(() -> {  
                        hasLoaded = true;  
                        SwingUtilities.invokeLater(() -> modelComboBox.showPopup());  
                    });  
                }  
            }  
            
            @Override  
            public void popupMenuWillBecomeInvisible(PopupMenuEvent e) {}  
            
            @Override  
            public void popupMenuCanceled(PopupMenuEvent e) {}  
        }); 

        String savedModel = prefs.get(PREF_MODEL, modelOptions[0]);  
        modelComboBox.setSelectedItem(savedModel);  
        modelComboBox.addActionListener(e -> prefs.put(PREF_MODEL, (String) modelComboBox.getSelectedItem()));  
    
        configPanel.add(new JLabel("模型选择: "));  
        configPanel.add(modelComboBox);  
    
        gbc.gridy = 0;  
        topPanel.add(configPanel, gbc);  
    
        // 输入面板  
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));  
        inputPanel.setBorder(BorderFactory.createTitledBorder("漏洞名称"));  
    
        // 仍然使用JTextArea但将其配置为单行显示  
        inputArea = new JTextArea(1, 20); // 将行数改为1  
        inputArea.setLineWrap(true);  
        inputArea.setWrapStyleWord(true);  
        // 禁止换行输入  
        inputArea.addKeyListener(new KeyAdapter() {  
            @Override  
            public void keyPressed(KeyEvent e) {  
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {  
                    e.consume(); // 消费掉回车键事件  
                    performAnalysis(); // 可选：按回车时触发分析  
                }  
            }  
        });  

        inputArea.getDocument().addDocumentListener(new DocumentListener() {  
            private void handleChange() {  
                if (currentState == AnalysisState.ANALYZING) {  
                    return;  
                }  
                
                String currentText = inputArea.getText().trim();  
                if (currentText.isEmpty()) {  
                    updateUIState(AnalysisState.READY);  
                    clearResults();  
                    return;  
                }  
                
                if (vulnInfoMap.containsKey(currentText)) {  
                    // 显示已有结果  
                    displayVulnInfo(vulnInfoMap.get(currentText));  
                    updateUIState(AnalysisState.RESULT_SHOWN);  
                    vulnHistoryList.setSelectedValue(currentText, true);  
                } else {  
                    // 准备分析新内容  
                    updateUIState(AnalysisState.READY);  
                    clearResults();  
                }  
            }  
        
            @Override  
            public void insertUpdate(DocumentEvent e) { handleChange(); }  
            @Override  
            public void removeUpdate(DocumentEvent e) { handleChange(); }  
            @Override  
            public void changedUpdate(DocumentEvent e) { handleChange(); }  
        });
    
        // 创建一个包含输入框和按钮的面板  
        JPanel inputControlPanel = new JPanel(new BorderLayout(5, 0));  
        inputControlPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));  
        JScrollPane scrollPane = new JScrollPane(inputArea) {  
            @Override  
            public Dimension getPreferredSize() {  
                // 控制滚动面板的高度  
                Dimension d = super.getPreferredSize();  
                d.height = 25; // 固定高度为25像素  
                return d;  
            }  
        };  
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);  
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER);  
        inputControlPanel.add(scrollPane, BorderLayout.CENTER);  
    
        // 创建按钮面板  
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));  

        // 分析按钮使用主色调  
        analyzeButton = new JButton("开始分析");  
        analyzeButton.setBackground(new Color(0, 120, 212));  
        analyzeButton.setForeground(Color.WHITE);  
        analyzeButton.setFocusPainted(false);  

        // 重新分析按钮使用次要色调  
        reAnalyzeButton = new JButton("重新分析");  // 使用类成员变量  
        reAnalyzeButton.setEnabled(false);  

        // 添加按钮事件监听器  
        analyzeButton.addActionListener(e -> performAnalysis());  
        reAnalyzeButton.addActionListener(e -> executeAnalysis());  

        buttonPanel.add(reAnalyzeButton);  
        buttonPanel.add(analyzeButton);  
        inputControlPanel.add(buttonPanel, BorderLayout.EAST);
        
        inputPanel.add(inputControlPanel, BorderLayout.CENTER);  
        
        gbc.gridy = 1;  
        topPanel.add(inputPanel, gbc);  
    
        // 结果面板  
        JPanel resultPanel = new JPanel(new GridBagLayout());  
        GridBagConstraints resultGbc = new GridBagConstraints();  
        resultGbc.fill = GridBagConstraints.BOTH;  
        resultGbc.weightx = 1.0;  
        resultGbc.insets = new Insets(2, 5, 2, 5);  
    
        // 漏洞类型  
        resultGbc.gridy = 0;  
        resultGbc.weighty = 0.1;  
        JPanel vulnTypePanel = new JPanel(new BorderLayout());  
        vulnTypePanel.setBorder(BorderFactory.createTitledBorder("漏洞类型"));  
        vulnTypeArea = new JTextArea(2, 20);  
        vulnTypeArea.setLineWrap(true);  
        vulnTypeArea.setWrapStyleWord(true);  
        vulnTypeArea.setEditable(false);  
        vulnTypePanel.add(new JScrollPane(vulnTypeArea), BorderLayout.CENTER);  
        resultPanel.add(vulnTypePanel, resultGbc);  
    
        // 漏洞描述  
        resultGbc.gridy = 1;  
        resultGbc.weighty = 0.4;  
        JPanel vulnDescPanel = new JPanel(new BorderLayout());  
        vulnDescPanel.setBorder(BorderFactory.createTitledBorder("漏洞描述"));  
        vulnDescArea = new JTextArea(8, 20);  
        vulnDescArea.setLineWrap(true);  
        vulnDescArea.setWrapStyleWord(true);  
        vulnDescArea.setEditable(false);  
        vulnDescPanel.add(new JScrollPane(vulnDescArea), BorderLayout.CENTER);  
        resultPanel.add(vulnDescPanel, resultGbc);  
    
        // 修复建议  
        resultGbc.gridy = 2;  
        resultGbc.weighty = 0.4;  
        JPanel vulnFixPanel = new JPanel(new BorderLayout());  
        vulnFixPanel.setBorder(BorderFactory.createTitledBorder("修复建议"));  
        vulnFixArea = new JTextArea(8, 20);  
        vulnFixArea.setLineWrap(true);  
        vulnFixArea.setWrapStyleWord(true);  
        vulnFixArea.setEditable(false);  
        vulnFixPanel.add(new JScrollPane(vulnFixArea), BorderLayout.CENTER);  
        resultPanel.add(vulnFixPanel, resultGbc);  
    
        // 组装右侧面板  
        rightPanel.add(topPanel, BorderLayout.NORTH);  
        rightPanel.add(resultPanel, BorderLayout.CENTER);  
    
        // 分割面板  
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);  
        splitPane.setDividerLocation(200);  
        mainPanel.add(splitPane, BorderLayout.CENTER);  
    
        // 历史记录点击事件  
        vulnHistoryList.addListSelectionListener(e -> {  
            if (!e.getValueIsAdjusting()) {  
                String selectedVuln = vulnHistoryList.getSelectedValue();  
                if (selectedVuln != null) {  
                    // 只在用户实际点击选择时更新输入框  
                    if (!selectedVuln.equals(inputArea.getText().trim())) {  
                        inputArea.setText(selectedVuln);  
                    }  
                }  
            }  
        });
    
        // 设置边距  
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));  
    
        callbacks.customizeUiComponent(mainPanel);  
        callbacks.addSuiteTab(this);  
    }

    private void displayVulnInfo(VulnInfo info) {  
        vulnTypeArea.setText(info.type);  
        vulnDescArea.setText(info.description);  
        vulnFixArea.setText(info.fix);  
    }  

    private void performAnalysis() {  
        String vulnName = inputArea.getText().trim();  
        if (vulnName.isEmpty()) {  
            showError("请输入漏洞名称");  
            return;  
        }  
    
        updateUIState(AnalysisState.ANALYZING);  
        executeAnalysis();  
    } 
    
    private void executeAnalysis() {  
        new SwingWorker<Void, Void>() {  
            @Override  
            protected Void doInBackground() throws Exception {  
                try {  
                    String vulnName = inputArea.getText().trim();  
                    URL url = new URL("http://127.0.0.1:11434/api/chat");  
                    byte[] request = buildHttpRequest(url, vulnName);  
                    IHttpService httpService = helpers.buildHttpService("127.0.0.1", 11434, false);  
                    
                    IHttpRequestResponse response = callbacks.makeHttpRequest(httpService, request);  
                    
                    if (response != null && response.getResponse() != null) {  
                        byte[] responseBytes = response.getResponse();  
                        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);  
                        
                        int bodyOffset = responseInfo.getBodyOffset();  
                        String responseBody = new String(responseBytes, bodyOffset, responseBytes.length - bodyOffset, "UTF-8");  
                        
                        if (responseInfo.getStatusCode() == 200) {  
                            parseAndDisplayResponse(responseBody);  
                        } else {  
                            showError("请求失败，状态码: " + responseInfo.getStatusCode());  
                        }  
                    }  
                    
                } catch (Exception e) {  
                    e.printStackTrace(stdout);  
                    showError("执行失败: " + e.getMessage());  
                    // 发生错误时恢复到 READY 状态  
                    SwingUtilities.invokeLater(() -> updateUIState(AnalysisState.READY));  
                    return null;  
                }  
                return null;  
            }  
            
            @Override  
            protected void done() {  
                // 只有在成功完成时才更新状态为 RESULT_SHOWN  
                if (!isCancelled()) {  
                    updateUIState(AnalysisState.RESULT_SHOWN);  
                }  
            }  
        }.execute();  
    }

    private void clearResults() {  
        vulnTypeArea.setText("");  
        vulnDescArea.setText("");  
        vulnFixArea.setText("");  
        // 清除结果时，如果不是在分析中，就重置状态为 READY  
        if (currentState != AnalysisState.ANALYZING) {  
            updateUIState(AnalysisState.READY);  
        }  
    }

    private byte[] buildHttpRequest(URL url, String prompt) throws Exception {  
        List<String> headers = new ArrayList<>();  
        headers.add("POST " + url.getPath() + " HTTP/1.1");  
        headers.add("Host: " + url.getHost() + ":11434");  
        headers.add("Content-Type: application/json");  
        headers.add("Accept: */*");  

        JSONObject message1 = new JSONObject();  
        message1.put("role", "system");  
        message1.put("content", buildSystemPrompt());  

        JSONObject message2 = new JSONObject();  
        message2.put("role", "user");  
        message2.put("content", prompt);  

        JSONArray messages = new JSONArray();  
        messages.put(message1);  
        messages.put(message2);  

        JSONObject jsonBody = new JSONObject();  
        jsonBody.put("model", modelComboBox.getSelectedItem().toString());  
        jsonBody.put("messages", messages);  
        jsonBody.put("stream", false);  

        String finalRequestBody = jsonBody.toString();  
        headers.add("Content-Length: " + finalRequestBody.length());  

        return helpers.buildHttpMessage(headers, finalRequestBody.getBytes());  
    }  

    private String buildSystemPrompt() {  
        return "# Role:漏洞修复专家\n" +  
               "# Profile \n" +
               "- author:lalala\n" +
               "- version: 1.0 \n" +  
               "- language: 中文 \n" +  
               "- description: 我是一个专门帮助用户分析和修复网络安全漏洞的专家。 \n\n" +  
               "## Goals \n" +  
               "1. 根据提供的网络安全漏洞名称，撰写详细的漏洞描述。 \n" +  
               "2. 提供最多四条技术性修复建议，以帮助用户有效解决漏洞问题。 \n" +  
               "3. 确保建议具有实用性和可操作性，以便用户能够轻松实施。 \n\n" +  
               "## Constraints \n" +  
               "1. 不提供任何管理层面的建议，仅限技术层面。 \n" +  
               "2. 不会生成任何可能被滥用或不当的建议。 \n" +  
               "3. 确保信息准确并符合当前的安全标准和最佳实践。 \n\n" +  
               "4. 确保按照示例输出纯文本格式，不要用markdown语法 \n\n" +  
               "## Skills \n" +  
               "1. 深入理解网络安全漏洞的类型、成因及其影响。 \n" +  
               "漏洞类型定义如下11种：\n" +  
               "配置部署漏洞\t主要包括备份文件、服务端漏洞等\n" +  
               "身份管理漏洞\t主要包括用户名枚举、任意用户注册等\n" +  
               "身份认证漏洞\t主要包括弱口令、暴力破解、登录绕过等\n" +  
               "身份授权漏洞\t主要包括越权、目录穿越等\n" +  
               "会话管理漏洞\t主要包括会话固定、会话劫持等\n" +  
               "输入验证漏洞\t主要包括SQL注入、XSS、命令注入等\n" +  
               "错误处理漏洞\t主要包括堆栈跟踪、错误处理不当等\n" +  
               "业务逻辑漏洞\t主要包括业务绕过、功能次数绕过等\n" +  
               "通信传输漏洞\t主要包括明文传输、协议缺陷等\n" +  
               "信息泄露漏洞\t主要包括信息泄露、过度暴露等\n" +  
               "其他类型漏洞\t其他非上述类型的漏洞\n\n" +  
               "2. 能够根据漏洞特性快速制定修复策略。 \n" +  
               "3. 熟练掌握不同类型漏洞的检测和修复技术。 \n" +  
               "4. 具备优秀的文字表达能力，以清晰传达技术建议。 \n\n" +  
               "## Workflow \n" +  
               "1. 接收用户提供的漏洞名称。 \n" +  
               "2. 分析漏洞的潜在影响和常见表现形式。 \n" +  
               "3.判断漏洞类型（11种中进行判断）\n" +  
               "4. 攥写漏洞描述，解释其成因和可能的攻击方式。 \n" +  
               "5. 提供技术性修复建议，确保建议具体且可操作。 \n" +  
               "## output example \n" +  
               "漏洞名称：账号枚举 \n" +  
               "漏洞类型：身份管理漏洞\n" +  
               "漏洞描述：账号枚举是一种安全漏洞，攻击者可以通过该漏洞获取系统中有效用户账号的信息。这种漏洞通常出现在用户注册、登录或忘记密码等功能中。当系统在处理这些请求时，如果没有正确地处理失败的用户名或密码尝试，就可能向攻击者泄露有效账号的存在。 \n" +  
               "修复建议： \n" +  
               "1. 对于无效的用户名和密码组合，返回相同的错误消息，如\"用户名或密码错误\"，避免暴露账号是否存在的信息。 \n" +  
               "2. 实现登录尝试次数的限制，例如，如果用户在短时间内多次尝试登录失败，则暂时锁定其账户或要求通过其他方式进行验证。";  
    }  

    private String formatFixSuggestions(String text) {  
        String[] lines = text.split("\n");  
        StringBuilder formatted = new StringBuilder();  
        
        for (String line : lines) {  
            line = line.trim();  
            if (line.matches("^\\d+\\..*")) {  
                formatted.append(line).append("\n");  
            } else {  
                formatted.append(line).append("\n");  
            }  
        }  
        
        return formatted.toString().trim();  
    }  

    private void parseAndDisplayResponse(String responseBody) {  
        try {  
            JSONObject json = new JSONObject(responseBody);  
            
            if (!json.has("message") || !json.getJSONObject("message").has("content")) {  
                stdout.println("[ERROR] 响应格式不正确");  
                showError("响应格式不正确");  
                return;  
            }  
            
            String text = json.getJSONObject("message").getString("content");  
            
            Pattern typePattern = Pattern.compile("漏洞类型：([^\\n]+)");  
            Pattern descPattern = Pattern.compile("漏洞描述：\\s*([\\s\\S]+?)(?=修复建议|$)");  
            Pattern fixPattern = Pattern.compile("修复建议：\\s*([\\s\\S]+?)(?=进一步支持|$)");  
            
            Matcher typeMatcher = typePattern.matcher(text);  
            Matcher descMatcher = descPattern.matcher(text);  
            Matcher fixMatcher = fixPattern.matcher(text);  
            
            if (typeMatcher.find() && descMatcher.find() && fixMatcher.find()) {  
                final String vulnName = inputArea.getText().trim();  
                final String vulnType = typeMatcher.group(1).trim();  
                final String vulnDesc = descMatcher.group(1).trim();  
                final String vulnFix = formatFixSuggestions(fixMatcher.group(1).trim());  
                
                SwingUtilities.invokeLater(() -> {  
                    try {  
                        updateUIWithResults(vulnName, vulnType, vulnDesc, vulnFix);  
                    } catch (Exception e) {  
                        e.printStackTrace(stdout);  
                        showError("更新显示内容时发生错误: " + e.getMessage());  
                    }  
                });  
            } else {  
                stdout.println("[WARNING] 未能匹配所有必要的信息");  
                stdout.println("[DEBUG] 原始响应文本：\n" + text);  
                showWarning("响应格式不完整，请检查响应内容");  
            }  
                
        } catch (Exception e) {  
            stdout.println("[ERROR] 解析响应失败: " + e.getMessage());  
            e.printStackTrace(stdout);  
            showError("解析响应失败: " + e.getMessage());  
        }  
    }  

    private void updateUIWithResults(String vulnName, String vulnType, String vulnDesc, String vulnFix) {  
        vulnTypeArea.setText(vulnType);  
        vulnDescArea.setText(vulnDesc);  
        vulnFixArea.setText(vulnFix);  
    
        VulnInfo info = new VulnInfo(vulnType, vulnDesc, vulnFix);  
        vulnInfoMap.put(vulnName, info);  
        
        if (!listModel.contains(vulnName)) {  
            listModel.addElement(vulnName);  
        }  
        vulnHistoryList.setSelectedValue(vulnName, true);  
        
        // 保存更新后的数据  
        saveData();  
        
        // 更新UI状态  
        updateUIState(AnalysisState.RESULT_SHOWN);  
    }

    private void showError(String message) {  
        SwingUtilities.invokeLater(() ->   
            JOptionPane.showMessageDialog(mainPanel, message, "错误", JOptionPane.ERROR_MESSAGE)  
        );  
    }  

    private void showWarning(String message) {  
        SwingUtilities.invokeLater(() ->   
            JOptionPane.showMessageDialog(mainPanel, message, "警告", JOptionPane.WARNING_MESSAGE)  
        );  
    }  

    @Override  
    public String getTabCaption() {  
        return "漏洞分析";  
    }  

    @Override  
    public Component getUiComponent() {  
        return mainPanel;  
    }  
}