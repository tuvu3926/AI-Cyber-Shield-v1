from flask import Blueprint, current_app, jsonify, request, make_response
from datetime import datetime

history_bp = Blueprint("history", __name__, url_prefix="/api")


@history_bp.route("/history", methods=["GET", "DELETE"])
def history():
    repo = current_app.config["HISTORY_REPO"]
    
    # GET
    if request.method == "GET":
        raw_limit = request.args.get("limit", type=int)
        limit = raw_limit if raw_limit and raw_limit > 0 else None
        rows = repo.list_records(limit=limit)
        
        # Đảo ngược thứ tự để hiển thị mới nhất trước (tùy chọn)
        # rows = list(reversed(rows))  # Bỏ comment nếu muốn
        
        response = jsonify({
            "success": True, 
            "data": rows,
            "count": len(rows),
            "timestamp": datetime.now().isoformat()
        })
        
        # Headers ngăn cache
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response, 200
    
    # DELETE
    if request.method == "DELETE":
        try:
            # Lấy số lượng records trước khi xóa
            before_count = repo.get_record_count() if hasattr(repo, 'get_record_count') else len(repo.list_records())
            print(f">>> DELETE CALLED - Records before: {before_count}")
            
            # Thực hiện xóa
            repo.clear()  # Gọi method clear đã thêm
            
            # Kiểm tra sau khi xóa
            after_count = repo.get_record_count() if hasattr(repo, 'get_record_count') else len(repo.list_records())
            print(f">>> DELETE COMPLETED - Records after: {after_count}")
            
            response = jsonify({
                "success": True,
                "message": f"History cleared successfully",
                "deleted_count": before_count,
                "remaining_count": after_count
            })
            
            # Headers ngăn cache
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            
            return response, 200
            
        except Exception as e:
            current_app.logger.error(f"Error clearing history: {str(e)}", exc_info=True)
            return jsonify({
                "success": False,
                "message": f"Error clearing history: {str(e)}"
            }), 500