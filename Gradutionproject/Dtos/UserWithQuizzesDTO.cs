﻿namespace Gradutionproject.Dtos
{
    public class UserWithQuizzesDTO
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public List<QuizDto> Quizzes { get; set; }
    }
}
